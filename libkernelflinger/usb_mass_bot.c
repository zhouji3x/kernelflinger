/** @file
    Implementation of the USB mass storage Bulk-Only Transport protocol,
    according to USB Mass Storage Class Bulk-Only Transport, Revision 1.0.

    Copyright (c) 2007 - 2017, Intel Corporation. All rights reserved.<BR>
    This program and the accompanying materials
    are licensed and made available under the terms and conditions of the BSD License
    which accompanies this distribution.  The full text of the license may be found at
    http://opensource.org/licenses/bsd-license.php

    THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
    WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.


**/

#include <lib.h>
//#include <efiapi.h>
#include "storage.h"
#include "UsbIo.h"
#include "protocol/DevicePath.h"
#include "usb_mass_bot.h"

EFI_STATUS
usb_clear_endpoint_stall(EFI_USB_IO_PROTOCOL *usb_io, UINT8 addr)
{
	EFI_USB_DEVICE_REQUEST    request;
	EFI_STATUS                status;
	UINT32                    cmd_result;
	UINT32                    timeout;

	request.RequestType = USB_DEV_CLEAR_FEATURE_REQ_TYPE_E;
	request.Request     = USB_REQ_CLEAR_FEATURE;
	request.Value       = USB_FEATURE_ENDPOINT_HALT;
	request.Index       = addr;
	request.Length      = 0;
	timeout             = USB_BOOT_GENERAL_CMD_TIMEOUT / USB_MASS_1_MILLISECOND;

	status = uefi_call_wrapper( usb_io->UsbControlTransfer,
		   						7,
								usb_io,
								&request,
								EfiUsbNoData,
								timeout,
								NULL,
								0,
								&cmd_result);
	return status;
}

/**
  Reset the USB mass storage device by BOT protocol.
**/

static
EFI_STATUS
usb_bot_reset_device (
	VOID                    *context,
	BOOLEAN                 extended_verification
  )
{
  USB_BOT_PROTOCOL        *usb_bot;
  EFI_USB_DEVICE_REQUEST  request;
  EFI_STATUS              status;
  UINT32                  result;
  UINT32                  timeout;

  usb_bot = (USB_BOT_PROTOCOL *) context;

  if (extended_verification) {
    //
    // If we need to do strictly reset, reset its parent hub port
    //
    status = uefi_call_wrapper (usb_bot->UsbIo->UsbPortReset, 1, usb_bot->UsbIo);
    if (EFI_ERROR (status)) {
      return EFI_DEVICE_ERROR;
    }
  }

  //
  // Issue a class specific Bulk-Only Mass Storage Reset request,
  // according to section 3.1 of USB Mass Storage Class Bulk-Only Transport Spec, v1.0.
  //
  request.RequestType = 0x21;
  request.Request     = USB_BOT_RESET_REQUEST;
  request.Value       = 0;
  request.Index       = usb_bot->Interface.InterfaceNumber;
  request.Length      = 0;
  timeout             = USB_BOT_RESET_DEVICE_TIMEOUT / USB_MASS_1_MILLISECOND;

  status = uefi_call_wrapper( usb_bot->UsbIo->UsbControlTransfer,
		 					7,
                            usb_bot->UsbIo,
                            &request,
                            EfiUsbNoData,
                            timeout,
                            NULL,
                            0,
                            &result
                            );

  if (EFI_ERROR (status)) {
    return EFI_DEVICE_ERROR;
  }

  //
  // The device shall NAK the host's request until the reset is
  // complete. We can use this to sync the device and host. For
  // now just stall 100ms to wait for the device.
  //
  uefi_call_wrapper (BS->Stall, 1, USB_BOT_RESET_DEVICE_STALL);

  //
  // Clear the Bulk-In and Bulk-Out stall condition.
  //
  usb_clear_endpoint_stall (usb_bot->UsbIo, usb_bot->BulkInEndpoint->EndpointAddress);
  usb_clear_endpoint_stall (usb_bot->UsbIo, usb_bot->BulkOutEndpoint->EndpointAddress);

  return status;
}
/**
  Send the command to the device using Bulk-Out endpoint.

  This function sends the command to the device using Bulk-Out endpoint.
  BOT transfer is composed of three phases: Command, Data, and Status.
  This is the Command phase.
**/

static
EFI_STATUS
usb_bot_send_command (
	USB_BOT_PROTOCOL         *usb_bot,
	UINT8                    *cmd,
	UINT8                    cmd_len,
	EFI_USB_DATA_DIRECTION   data_dir,
	UINT32                   trans_len,
	UINT8                    lun
  )
{
  USB_BOT_CBW               cbw;
  EFI_STATUS                status;
  UINT32                    result;
  UINTN                     data_len;
  UINTN                     timeout;

  ASSERT ((cmd_len > 0) && (cmd_len <= USB_BOT_MAX_CMDLEN));

  //
  // Fill in the Command Block Wrapper.
  //
  cbw.Signature = USB_BOT_CBW_SIGNATURE;
  cbw.Tag       = usb_bot->CbwTag;
  cbw.DataLen   = trans_len;
  cbw.Flag      = (UINT8) ((data_dir == EfiUsbDataIn) ? 0x80 : 0);
  cbw.Lun       = lun;
  cbw.CmdLen    = cmd_len;

  ZeroMem (cbw.CmdBlock, USB_BOT_MAX_CMDLEN);
  CopyMem (cbw.CmdBlock, cmd, cmd_len);

  result  = 0;
  data_len = sizeof (USB_BOT_CBW);
  timeout = USB_BOT_SEND_CBW_TIMEOUT / USB_MASS_1_MILLISECOND;

  //
  // Use USB I/O Protocol to send the Command Block Wrapper to the device.
  //
  status = uefi_call_wrapper(usb_bot->UsbIo->UsbBulkTransfer,
		 					6,
                            usb_bot->UsbIo,
                            usb_bot->BulkOutEndpoint->EndpointAddress,
                            &cbw,
                            &data_len,
                            timeout,
                            &result
                            );
  if (EFI_ERROR (status)) {
    if (USB_IS_ERROR (result, EFI_USB_ERR_STALL) && data_dir == EfiUsbDataOut) {
      //
      // Respond to Bulk-Out endpoint stall with a Reset Recovery,
      // according to section 5.3.1 of USB Mass Storage Class Bulk-Only Transport Spec, v1.0.
      //
      usb_bot_reset_device (usb_bot, FALSE);
    } else if (USB_IS_ERROR (result, EFI_USB_ERR_NAK)) {
      status = EFI_NOT_READY;
    }
  }

  return status;
}

/**
  Transfer the data between the device and host.

  This function transfers the data between the device and host.
  BOT transfer is composed of three phases: Command, Data, and Status.
  This is the Data phase.
**/
static
EFI_STATUS
usb_bot_data_transfer (
	USB_BOT_PROTOCOL         *usb_bot,
	EFI_USB_DATA_DIRECTION   data_dir,
	OUT UINT8                *data,
	OUT UINTN                *trans_len,
	UINT32                   timeout
  )
{
  EFI_USB_ENDPOINT_DESCRIPTOR *endpoint;
  EFI_STATUS                  status;
  UINT32                      result;

  //
  // If no data to transfer, just return EFI_SUCCESS.
  //
  if ((data_dir == EfiUsbNoData) || (*trans_len == 0)) {
    return EFI_SUCCESS;
  }

  //
  // Select the endpoint then issue the transfer
  //
  if (data_dir == EfiUsbDataIn) {
    endpoint = usb_bot->BulkInEndpoint;
  } else {
    endpoint = usb_bot->BulkOutEndpoint;
  }

  result  = 0;
  timeout = timeout / USB_MASS_1_MILLISECOND;

  status = uefi_call_wrapper(usb_bot->UsbIo->UsbBulkTransfer,
		 					6,
                            usb_bot->UsbIo,
                            endpoint->EndpointAddress,
                            data,
                            trans_len,
                            timeout,
                            &result
                            );
  if (EFI_ERROR (status)) {
    if (USB_IS_ERROR (result, EFI_USB_ERR_STALL)) {
      DEBUG ((EFI_D_INFO, "usb_bot_data_transfer: (%r)\n", status));
      DEBUG ((EFI_D_INFO, "usb_bot_data_transfer: DataIn Stall\n"));
      usb_clear_endpoint_stall (usb_bot->UsbIo, endpoint->EndpointAddress);
    } else if (USB_IS_ERROR (result, EFI_USB_ERR_NAK)) {
      status = EFI_NOT_READY;
    } else {
      DEBUG ((EFI_D_ERROR, "usb_bot_data_transfer: (%r)\n", status));
    }
    if(status == EFI_TIMEOUT){
      usb_bot_reset_device(usb_bot, FALSE);
    }
  }

  return status;
}

/**
  Get the command execution status from device.
**/
static
EFI_STATUS
usb_bot_get_status (
	USB_BOT_PROTOCOL      *usb_bot,
	__attribute__((unused)) UINT32 trans_len,
	UINT8                 *cmd_status
  )
{
  USB_BOT_CSW               csw;
  UINTN                     len;
  UINT8                     endpoint;
  EFI_STATUS                status;
  UINT32                    result;
  EFI_USB_IO_PROTOCOL       *usb_io;
  UINT32                    idx;
  UINTN                     timeout;

  *cmd_status = USB_BOT_COMMAND_ERROR;
  status     = EFI_DEVICE_ERROR;
  endpoint   = usb_bot->BulkInEndpoint->EndpointAddress;
  usb_io      = usb_bot->UsbIo;
  timeout    = USB_BOT_RECV_CSW_TIMEOUT / USB_MASS_1_MILLISECOND;

  for (idx = 0; idx < USB_BOT_RECV_CSW_RETRY; idx++) {
    //
    // Attemp to the read Command Status Wrapper from bulk in endpoint
    //
    ZeroMem (&csw, sizeof (USB_BOT_CSW));
    result = 0;
    len    = sizeof (USB_BOT_CSW);
    status = uefi_call_wrapper (usb_io->UsbBulkTransfer,
								6,
								usb_io,
								endpoint,
								&csw,
								&len,
								timeout,
								&result
								);
    if (EFI_ERROR(status)) {
      if (USB_IS_ERROR (result, EFI_USB_ERR_STALL)) {
        usb_clear_endpoint_stall (usb_io, endpoint);
      }
      continue;
    }

    if (csw.Signature != USB_BOT_CSW_SIGNATURE) {
      //
      // CSW is invalid, so perform reset recovery
      //
      status = usb_bot_reset_device (usb_bot, FALSE);
    } else if (csw.CmdStatus == USB_BOT_COMMAND_ERROR) {
      //
      // Respond phase error also needs reset recovery
      //
      status = usb_bot_reset_device (usb_bot, FALSE);
    } else {
      *cmd_status = csw.CmdStatus;
      break;
    }
  }
  //
  //The tag is increased even if there is an error.
  //
  usb_bot->CbwTag++;

  return status;
}

/**
  Call the USB Mass Storage Class BOT protocol to issue
  the command/data/status circle to execute the commands.
**/
static
EFI_STATUS
usb_bot_command (
	VOID                    *context,
	VOID                    *cmd,
	UINT8                   cmd_len,
	EFI_USB_DATA_DIRECTION  data_dir,
	VOID                    *data,
	UINT32                  data_len,
	UINT8                   lun,
	UINT32                  timeout,
	UINT32                  *cmd_status
  )
{
  USB_BOT_PROTOCOL          *usb_bot;
  EFI_STATUS                status;
  UINTN                     trans_len;
  UINT8                     result;

  *cmd_status  = USB_MASS_CMD_FAIL;
  usb_bot      = (USB_BOT_PROTOCOL *) context;

  //
  // Send the command to the device. Return immediately if device
  // rejects the command.
  //
  status = usb_bot_send_command (usb_bot, cmd, cmd_len, data_dir, data_len, lun);
  if (EFI_ERROR (status)) {
    DEBUG ((EFI_D_ERROR, "usb_bot_command: usb_bot_send_command (%r)\n", status));
    return status;
  }

  //
  // Transfer the data. Don't return immediately even data transfer
  // failed. The host should attempt to receive the CSW no matter
  // whether it succeeds or fails.
  //
  trans_len = (UINTN) data_len;
  usb_bot_data_transfer (usb_bot, data_dir, data, &trans_len, timeout);

  //
  // Get the status, if that succeeds, interpret the result
  //
  status = usb_bot_get_status (usb_bot, data_len, &result);
  if (EFI_ERROR (status)) {
    DEBUG ((EFI_D_ERROR, "usb_bot_command: usb_bot_get_status (%r)\n", status));
    return status;
  }

  if (result == 0) {
    *cmd_status = USB_MASS_CMD_SUCCESS;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
usb_command_with_retry (VOID          			*context,
						VOID                    *cmd,
						UINT8                   cmd_len,
						EFI_USB_DATA_DIRECTION  data_dir,
						VOID                    *data,
						UINT32                  data_len,
						UINT8					lun,
						UINT32                  timeout,
						UINT32                  *cmd_status
						)
{
	EFI_STATUS             status;
	UINTN                  retry;
	VOID                   *timeout_evt;

	retry  = 0;
	status = EFI_SUCCESS;
	status = uefi_call_wrapper(BS->CreateEvent,
							  5,
							  EVT_TIMER,
							  TPL_CALLBACK,
							  NULL,
							  NULL,
							  &timeout_evt);
	if (EFI_ERROR (status)){
		debug(L"usb_command_with_retry: no event create\n");
		return status;
	}

	status = uefi_call_wrapper(BS->SetTimer,
							  3,
							  timeout_evt,
							  TimerRelative,
							  EFI_TIMER_PERIOD_SECONDS(60));
	if (EFI_ERROR (status)) {
		debug(L"usb_command_with_retry: no timer set\n");
		goto EXIT;
	}

	while (EFI_ERROR (uefi_call_wrapper(BS->CheckEvent, 1, timeout_evt))) {
		status = usb_bot_command(context,
								 cmd,
								 cmd_len,
								 data_dir,
								 data,
								 data_len,
								 lun,
								 timeout,
								 cmd_status);

	if (status == EFI_SUCCESS || status == EFI_NO_MEDIA)
		break;

	if (status == EFI_NOT_READY)
		continue;

	if (retry++ >= USB_COMMAND_RETRY)
		break;
  }

EXIT:
	if (timeout_evt != NULL) {
		uefi_call_wrapper(BS->CloseEvent, 1, timeout_evt);
	}
	return status;
}
