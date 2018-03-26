/*
 * PRU IEP Driver
 *
 * Copyright (C) 2017 Texas Instruments Incorporated - http://www.ti.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef ICSS_TIMESYNC_H_
#define ICSS_TIMESYNC_H_

/**
 * @def PTP_SYNC_MSG_ID
 *      Sync message ID value
 */
#define PTP_SYNC_MSG_ID                     0x00
/**
 * @def PTP_DLY_REQ_MSG_ID
 *      Delay request message ID value
 */
#define PTP_DLY_REQ_MSG_ID                  0x01
/**
 * @def PTP_PDLY_REQ_MSG_ID
 *      PDelay request message ID value
 */
#define PTP_PDLY_REQ_MSG_ID                 0x02
/**
 * @def PTP_PDLY_RSP_MSG_ID
 *      PDelay response message ID value
 */
#define PTP_PDLY_RSP_MSG_ID                 0x03
/**
 * @def PTP_FOLLOW_UP_MSG_ID
 *      Follow up message ID value
 */
#define PTP_FOLLOW_UP_MSG_ID                0x08
/**
 * @def PTP_DLY_RESP_MSG_ID
 *      Delay response message ID value
 */
#define PTP_DLY_RESP_MSG_ID                 0x09
/**
 * @def PTP_PDLY_RESP_FLW_UP_MSG_ID
 *      PDelay response follow up message ID value
 */
#define PTP_PDLY_RESP_FLW_UP_MSG_ID         0x0A
/**
 * @def PTP_ANNOUNCE_MSG_ID
 *      Announce message ID value
 */
#define PTP_ANNOUNCE_MSG_ID                 0x0B
/**
 * @def PTP_MGMT_MSG_ID
 *      Management message ID value
 */
#define PTP_MGMT_MSG_ID                     0x0D

/**
 * @def GPTP_NUM_DOMAINS
 *      Number of domains supported by GPTP implementation
 */
#define GPTP_NUM_DOMAINS                        2

#define GPTP_BASE_ADDR_OFFSET                   0x8

#define RX_SYNC_TIMESTAMP_OFFSET_P1             (GPTP_BASE_ADDR_OFFSET + 0)                  /* 12 bytes */
#define RX_PDELAY_REQ_TIMESTAMP_OFFSET_P1       (RX_SYNC_TIMESTAMP_OFFSET_P1 + 12)           /* 12 bytes */
#define RX_PDELAY_RESP_TIMESTAMP_OFFSET_P1      (RX_PDELAY_REQ_TIMESTAMP_OFFSET_P1 + 12)     /* 12 bytes */
#define RX_SYNC_TIMESTAMP_OFFSET_P2             (RX_PDELAY_RESP_TIMESTAMP_OFFSET_P1 + 12)    /* 12 bytes */
#define RX_PDELAY_REQ_TIMESTAMP_OFFSET_P2       (RX_SYNC_TIMESTAMP_OFFSET_P2 + 12)           /* 12 bytes */
#define RX_PDELAY_RESP_TIMESTAMP_OFFSET_P2      (RX_PDELAY_REQ_TIMESTAMP_OFFSET_P2 + 12)     /* 12 bytes */
#define TIMESYNC_DOMAIN_NUMBER_LIST             (RX_PDELAY_RESP_TIMESTAMP_OFFSET_P2 + 12)    /* 2 domains(2 bytes) supported in firmware */
#define P1_SMA_LINE_DELAY_OFFSET                (TIMESYNC_DOMAIN_NUMBER_LIST + 2)            /* 4 bytes */
#define P2_SMA_LINE_DELAY_OFFSET                (P1_SMA_LINE_DELAY_OFFSET + 4)               /* 4 bytes */
#define TIMESYNC_SECONDS_COUNT_OFFSET           (P2_SMA_LINE_DELAY_OFFSET + 4)               /* 6 bytes */
#define TIMESYNC_TC_RCF_OFFSET                  (TIMESYNC_SECONDS_COUNT_OFFSET + 6)          /* 4 bytes */
#define DUT_IS_MASTER_OFFSET                    (TIMESYNC_TC_RCF_OFFSET + 4)                 /* 1 byte. Tells if port is master or slave */
#define MASTER_PORT_NUM_OFFSET                  (DUT_IS_MASTER_OFFSET + 1)                   /* 1 byte */
#define SYNC_MASTER_MAC_OFFSET                  (MASTER_PORT_NUM_OFFSET + 1)                 /* 6 bytes */
#define TX_TS_NOTIFICATION_OFFSET_SYNC_P1       (SYNC_MASTER_MAC_OFFSET + 6)                 /* 1 byte */
#define TX_TS_NOTIFICATION_OFFSET_PDEL_REQ_P1   (TX_TS_NOTIFICATION_OFFSET_SYNC_P1 + 1)      /* 1 byte */
#define TX_TS_NOTIFICATION_OFFSET_PDEL_RES_P1   (TX_TS_NOTIFICATION_OFFSET_PDEL_REQ_P1 + 1)  /* 1 byte */
#define TX_TS_NOTIFICATION_OFFSET_SYNC_P2       (TX_TS_NOTIFICATION_OFFSET_PDEL_RES_P1 + 1)  /* 1 byte */
#define TX_TS_NOTIFICATION_OFFSET_PDEL_REQ_P2   (TX_TS_NOTIFICATION_OFFSET_SYNC_P2 + 1)      /* 1 byte */
#define TX_TS_NOTIFICATION_OFFSET_PDEL_RES_P2   (TX_TS_NOTIFICATION_OFFSET_PDEL_REQ_P2 + 1)  /* 1 byte */
#define TX_SYNC_TIMESTAMP_OFFSET_P1             (TX_TS_NOTIFICATION_OFFSET_PDEL_RES_P2 + 1)  /* 12 bytes */
#define TX_PDELAY_REQ_TIMESTAMP_OFFSET_P1       (TX_SYNC_TIMESTAMP_OFFSET_P1 + 12)           /* 12 bytes */
#define TX_PDELAY_RESP_TIMESTAMP_OFFSET_P1      (TX_PDELAY_REQ_TIMESTAMP_OFFSET_P1 + 12)     /* 12 bytes */
#define TX_SYNC_TIMESTAMP_OFFSET_P2             (TX_PDELAY_RESP_TIMESTAMP_OFFSET_P1 + 12)    /* 12 bytes */
#define TX_PDELAY_REQ_TIMESTAMP_OFFSET_P2       (TX_SYNC_TIMESTAMP_OFFSET_P2 + 12)           /* 12 bytes */
#define TX_PDELAY_RESP_TIMESTAMP_OFFSET_P2      (TX_PDELAY_REQ_TIMESTAMP_OFFSET_P2 + 12)     /* 12 bytes */
#define TIMESYNC_CTRL_VAR_OFFSET                (TX_PDELAY_RESP_TIMESTAMP_OFFSET_P2 + 12)    /* 1 byte */
#define DISABLE_SWITCH_SYNC_RELAY_OFFSET        (TIMESYNC_CTRL_VAR_OFFSET + 1)               /* 1 byte */
#define MII_RX_CORRECTION_OFFSET                (DISABLE_SWITCH_SYNC_RELAY_OFFSET + 1)       /* 2 bytes */
#define MII_TX_CORRECTION_OFFSET                (MII_RX_CORRECTION_OFFSET + 2)               /* 2 bytes */
#define TIMESYNC_CMP1_CMP_OFFSET                (MII_TX_CORRECTION_OFFSET + 2)               /* 8 bytes */
#define TIMESYNC_SYNC0_CMP_OFFSET               (TIMESYNC_CMP1_CMP_OFFSET + 8)               /* 8 bytes */
#define TIMESYNC_CMP1_PERIOD_OFFSET             (TIMESYNC_SYNC0_CMP_OFFSET + 8)              /* 4 bytes */
#define TIMESYNC_SYNC0_WIDTH_OFFSET             (TIMESYNC_CMP1_PERIOD_OFFSET + 4)            /* 4 bytes */
#define SINGLE_STEP_IEP_OFFSET_P1               (TIMESYNC_SYNC0_WIDTH_OFFSET + 4)            /* 8 bytes */
#define SINGLE_STEP_SECONDS_OFFSET_P1           (SINGLE_STEP_IEP_OFFSET_P1 + 8)              /* 8 bytes */
#define SINGLE_STEP_IEP_OFFSET_P2               (SINGLE_STEP_SECONDS_OFFSET_P1 + 8)          /* 8 bytes */
#define SINGLE_STEP_SECONDS_OFFSET_P2           (SINGLE_STEP_IEP_OFFSET_P2 + 8)              /* 8 bytes */
#define LINK_LOCAL_FRAME_HAS_HSR_TAG            (SINGLE_STEP_SECONDS_OFFSET_P2 + 8)          /* 1 bytes */
#define PTP_PREV_TX_TIMESTAMP_P1                (LINK_LOCAL_FRAME_HAS_HSR_TAG + 1)           /* 8 bytes */
#define PTP_PREV_TX_TIMESTAMP_P2                (PTP_PREV_TX_TIMESTAMP_P1 + 8)               /* 8 bytes */
#define PTP_CLK_IDENTITY_OFFSET                 (PTP_PREV_TX_TIMESTAMP_P2 + 8)               /* 8 bytes */
#define PTP_SCRATCH_MEM                         (PTP_CLK_IDENTITY_OFFSET + 8)                /* 8 bytes */

#endif /* ICSS_TIMESYNC_H_ */
