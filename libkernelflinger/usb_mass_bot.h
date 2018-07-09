/** @file
   Definition for the USB mass storage Bulk-Only Transport protocol,
   based on the "Universal Serial Bus Mass Storage Class Bulk-Only
   Transport" Revision 1.0, September 31, 1999.

   Copyright (c) 2007 - 2011, Intel Corporation. All rights reserved.<BR>
   This program and the accompanying materials
   are licensed and made available under the terms and conditions of the BSD License
   which accompanies this distribution.  The full text of the license may be found at
   http://opensource.org/licenses/bsd-license.php

   THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
   WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

//
// Usb Bulk-Only class specfic request
//

#ifndef _EFI_USBMASS_BOT_H_
#define _EFI_USBMASS_BOT_H_

typedef struct _USB_MASS_TRANSPORT USB_MASS_TRANSPORT;
typedef struct _USB_MASS_DEVICE    USB_MASS_DEVICE;

#define USB_BOT_RESET_REQUEST    0xFF       ///< Bulk-Only Mass Storage Reset
#define USB_BOT_GETLUN_REQUEST   0xFE       ///< Get Max Lun
#define USB_BOT_CBW_SIGNATURE    0x43425355 ///< dCBWSignature, tag the packet as CBW
#define USB_BOT_CSW_SIGNATURE    0x53425355 ///< dCSWSignature, tag the packet as CSW
#define USB_BOT_MAX_LUN          0x0F       ///< Lun number is from 0 to 15
#define USB_BOT_MAX_CMDLEN       16         ///< Maxium number of command from command set

//
// Usb BOT command block status values
//
#define USB_BOT_COMMAND_OK       0x00 ///< Command passed, good status
#define USB_BOT_COMMAND_FAILED   0x01 ///< Command failed
#define USB_BOT_COMMAND_ERROR    0x02 ///< Phase error, need to reset the device

//
// Usb Bot retry to get CSW, refers to specification[BOT10-5.3, it says 2 times]
//
#define USB_BOT_RECV_CSW_RETRY   3

//
// Usb Bot wait device reset complete, set by experience
#define USB_BOT_RESET_DEVICE_STALL  (100 * USB_MASS_1_MILLISECOND)

// Usb Bot transport timeout, set by experience
//
#define USB_BOT_SEND_CBW_TIMEOUT     (3 * USB_MASS_1_SECOND)
#define USB_BOT_RECV_CSW_TIMEOUT     (3 * USB_MASS_1_SECOND)
#define USB_BOT_RESET_DEVICE_TIMEOUT (3 * USB_MASS_1_SECOND)
#define EFI_TIMER_PERIOD_SECONDS(Seconds)     ((UINT64)(Seconds) * 10000000)
#define USB_COMMAND_RETRY 5
#define USB_IS_IN_ENDPOINT(EndPointAddr)      (((EndPointAddr) & BIT7) == BIT7)
#define USB_IS_OUT_ENDPOINT(EndPointAddr)     (((EndPointAddr) & BIT7) == 0)
#define USB_IS_BULK_ENDPOINT(Attribute)       (((Attribute) & (BIT0 | BIT1)) == USB_ENDPOINT_BULK)
#define USB_IS_INTERRUPT_ENDPOINT(Attribute)  (((Attribute) & (BIT0 | BIT1)) == USB_ENDPOINT_INTERRUPT)
#define USB_IS_ERROR(Result, Error)           (((Result) & (Error)) != 0)

#define USB_MASS_1_MILLISECOND  1000
#define USB_MASS_1_SECOND       (1000 * USB_MASS_1_MILLISECOND)
#define USB_BOOT_GENERAL_CMD_TIMEOUT       (5 * USB_MASS_1_SECOND)

#define USB_MASS_CMD_SUCCESS    0
#define USB_MASS_CMD_FAIL       1
#define USB_MASS_CMD_PERSISTENT 2


#pragma pack(1)
///
/// The CBW (Command Block Wrapper) structures used by the USB BOT protocol.
///
typedef struct {
  UINT32              Signature;
  UINT32              Tag;
  UINT32              DataLen;  ///< Length of data between CBW and CSW
  UINT8               Flag;     ///< Bit 7, 0 ~ Data-Out, 1 ~ Data-In
  UINT8               Lun;      ///< Lun number. Bits 0~3 are used
  UINT8               CmdLen;   ///< Length of the command. Bits 0~4 are used
  UINT8               CmdBlock[USB_BOT_MAX_CMDLEN];
} USB_BOT_CBW;

///
/// The and CSW (Command Status Wrapper) structures used by the USB BOT protocol.
///
typedef struct {
  UINT32              Signature;
  UINT32              Tag;
  UINT32              DataResidue;
  UINT8               CmdStatus;
} USB_BOT_CSW;
#pragma pack()

typedef struct {
  //
  // Put Interface at the first field to make it easy to distinguish BOT/CBI Protocol instance
  //
  EFI_USB_INTERFACE_DESCRIPTOR  Interface;
  EFI_USB_ENDPOINT_DESCRIPTOR   *BulkInEndpoint;
  EFI_USB_ENDPOINT_DESCRIPTOR   *BulkOutEndpoint;
  UINT32                        CbwTag;
  EFI_USB_IO_PROTOCOL           *UsbIo;
} USB_BOT_PROTOCOL;

/**
  Call the USB Mass Storage Class BOT protocol to issue
  the command/data/status circle to execute the commands.
**/
EFI_STATUS
usb_command_with_retry (
		VOID                    *context,
		VOID                    *cmd,
		UINT8                   cmd_len,
		EFI_USB_DATA_DIRECTION  data_dir,
		VOID                    *data,
		UINT32                  data_len,
		UINT8                   lun,
		UINT32                  timeout,
		UINT32                  *cmd_status
  );

/**
  Initializes USB transport protocol.
**/
typedef
EFI_STATUS
(*USB_MASS_INIT_TRANSPORT) (
  IN  EFI_USB_IO_PROTOCOL     *Usb,
  OUT VOID                    **Context    OPTIONAL
  );

/**
  Execute USB mass storage command through the transport protocol.
**/
typedef
EFI_STATUS
(*USB_MASS_EXEC_COMMAND) (
  IN  VOID                    *Context,
  IN  VOID                    *Cmd,
  IN  UINT8                   CmdLen,
  IN  EFI_USB_DATA_DIRECTION  DataDir,
  IN  VOID                    *Data,
  IN  UINT32                  DataLen,
  IN  UINT8                   Lun,
  IN  UINT32                  Timeout,
  OUT UINT32                  *CmdStatus
  );

/**
  Reset the USB mass storage device by Transport protocol.
**/
typedef
EFI_STATUS
(*USB_MASS_RESET) (
  IN  VOID                    *Context,
  IN  BOOLEAN                 ExtendedVerification
  );

/**
  Get the max LUN (Logical Unit Number) of USB mass storage device.
**/
typedef
EFI_STATUS
(*USB_MASS_GET_MAX_LUN) (
  IN  VOID                    *Context,
  IN  UINT8                   *MaxLun
  );

/**
  Clean up the transport protocol's resource.
**/
typedef
EFI_STATUS
(*USB_MASS_CLEAN_UP) (
  IN  VOID                    *Context
  );

///
/// This structure contains information necessary to select the
/// proper transport protocol. The mass storage class defines
/// two transport protocols. One is the CBI, and the other is BOT.
/// CBI is being obseleted. The design is made modular by this
/// structure so that the CBI protocol can be easily removed when
/// it is no longer necessary.
///
struct _USB_MASS_TRANSPORT {
  UINT8                   Protocol;
  USB_MASS_INIT_TRANSPORT Init;        ///< Initialize the mass storage transport protocol
  USB_MASS_EXEC_COMMAND   ExecCommand; ///< Transport command to the device then get result
  USB_MASS_RESET          Reset;       ///< Reset the device
  USB_MASS_GET_MAX_LUN    GetMaxLun;   ///< Get max lun, only for bot
  USB_MASS_CLEAN_UP       CleanUp;     ///< Clean up the resources.
};

struct _USB_MASS_DEVICE {
  UINT32                    Signature;
  EFI_HANDLE                Controller;
  EFI_USB_IO_PROTOCOL       *UsbIo;
  EFI_DEVICE_PATH_PROTOCOL  *DevicePath;
  EFI_BLOCK_IO				BlockIo;
  EFI_BLOCK_IO_MEDIA        BlockIoMedia;
  BOOLEAN                   OpticalStorage;
  UINT8                     Lun;          ///< Logical Unit Number
  UINT8                     Pdt;          ///< Peripheral Device Type
  USB_MASS_TRANSPORT        *Transport;   ///< USB mass storage transport protocol
  VOID                      *Context;
  /*
  EFI_DISK_INFO_PROTOCOL    DiskInfo;
  USB_BOOT_INQUIRY_DATA     InquiryData;
  BOOLEAN                   Cdb16Byte;
  */
};

#define USB_MASS_DEVICE_FROM_BLOCK_IO(a) \
	        ((UINTN)a - offsetof(USB_MASS_DEVICE, BlockIo))
#endif
