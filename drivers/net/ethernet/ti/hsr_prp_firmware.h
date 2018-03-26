/*
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

#ifndef __ICSS_SWITCH_HSR_PRP_H
#define __ICSS_SWITCH_HSR_PRP_H

#define ETHER_TYPE_HSR                   0x892F  /* HSR ether type */
#define HSR_TAG_SIZE                     6       /* HSR tag size */
#define HSR_TAG_PATHID_OFFSET            2       /* Offset from the beginning
						  * of HSR tag to the path ID
						  */

#define LRE_HSR_MODE                      0x1E76
#define MODEH                             0x01
#define MODEN                             0x02
#define MODET                             0x03
#define MODEU                             0x04
#define MODEM                             0x05

/* PRU0 DMEM */
/* FOR DEBUG */
#define DBG_START                         0x1C00
#define DBG_NODE_TABLE_INSERTION_ERROR    (DBG_START + 4)
#define DBG_RXA_OVERFLOW                  (DBG_START + 8)
#define DBG_RXB_OVERFLOW                  (DBG_START + 12)

/* duplicate found in PRU0 for port duplicate rejection */
#define DBG_RXA_FWD_OVERFLOW              (DBG_START + 16)

#define DBG_RXB_FWD_OVERFLOW              (DBG_START + 20)

/* Count all SFD in PRU0 */
#define DBG_RXA_FAILACQU_QUEUE            (DBG_START + 24)

/* Count all SFD in PRU1 */
#define DBG_RXB_FAILACQU_QUEUE            (DBG_START + 28)

#define DBG_RXA_FWD_FAILACQU_QUEUE        (DBG_START + 32)
#define DBG_RXB_FWD_FAILACQU_QUEUE        (DBG_START + 36)

/* Counter incr when failing to access host queue */
#define DBG_DEBUG_1                       (DBG_START + 40)
#define DBG_DEBUG_2                       (DBG_START + 44)
#define DBG_DEBUG_3                       (DBG_START + 48)
#define DBG_DEBUG_4                       (DBG_START + 56)
/* END FOR DEBUG */

#define DUPLICATE_HOST_TABLE              0x0200
#define DUPLICATE_HOST_TABLE_END          0x19f4
#define NEXT_FREE_ADDRESS_NT_QUEUE        0x1B00
#define POINTERS_FREE_ADDR_NODETABLE      0x1B84

#define POINTERS_FREE_ADDR_NODETABLE_INIT 0x00800080

#define NEXT_FREE_ADDRESS_NT_QUEUE_INIT   0x04030201
#define NEXT_FREE_ADDRESS_NT_QUEUE_STEP   0x04040404

/* PRU1 DMEM */
#define DUPLICATE_PORT_TABLE_PRU0         0x0200
#define DUPLICATE_PORT_TABLE_PRU0_END     0x0df4
#define DUPLICATE_PORT_TABLE_PRU1         0x0E00
#define DUPLICATE_PORT_TABLE_PRU1_END     0x19f4

/* Offsets to ... */
/* Size of the node table [0..128] */
#define NODE_TABLE_SIZE                   0x1C00
/* Busy slave flag and busy master flag for 3 lock
 * used to protect the node table
 */
#define NODE_TABLE_ARBITRATION            0x1C04
/* Size and setup (N and M) of duplicate host table */
#define DUPLICATE_HOST_TABLE_SIZE         0x1C08
/* Size and setup (N and M) of duplicate port table (HSR Only) */
#define DUPLICATE_PORT_TABLE_SIZE         0x1C1C
/* Time after which a node entry is cleared (10ms resolution) */
#define NODE_FORGET_TIME                  0x1C20
/* Time after which an entry is removed from the dup table (10ms resolution) */
#define DUPLI_FORGET_TIME                 0x1C24
/* Supervision frame Counter minimum difference to detect a broken path */
#define PATH_BROKEN_NB_FRAM_DIFF          0x1C28
/* Time interval to check the port duplicate table */
#define DUPLI_PORT_CHECK_RESO             0x1C2C
/* Time interval to check the host duplicate table */
#define DUPLI_HOST_CHECK_RESO             0x1C30
/* Time interval to check the node duplicate table */
#define NODETABLE_CHECK_RESO              0x1C34
/* NodeTable | Host | Port */
#define HOST_TIMER_CHECK_FLAGS            0x1C38
/* Arbitration flag for the host duplicate t */
#define HOST_DUPLICATE_ARBITRATION        0x1C3C
/* Time counter to trigger the host dup table check task */
#define ICSS_FIRMWARE_RELEASE             0x1C40
/* Time counter to trigger the Node_Table check task */
#define RED_FIRMWARE_RELEASE              0x1C44
/* Supervision address in HSR */
#define SUP_ADDR                          0x1C4C
#define SUP_ADDR_LOW                      0x1C50

/* Time in TimeTicks (1/100s) */
#define DUPLICATE_FORGET_TIME_400_MS      40
/* Time in TimeTicks (1/100s) */
#define DUPLICATE_FORGET_TIME_400_MS_PRP  0x0028
/* Time in TimeTicks (1/100s) */
#define NODE_FORGET_TIME_60000_MS         6000
/* Time in TimeTicks (1/100s) */
#define CONST_NODE_FORGET_TIME_60000_MS   0x1770
/* Max value possible for timelastseen before wrap around */
#define MAX_FORGET_TIME_BEFORE_WRAP       0xFFDF
/* Maximum number of node table entries used for network supervision */
#define NODE_TABLE_SIZE_MAX               128
/* Number of entries used internally by PRU */
#define NODE_TABLE_NARROW_ENTRIES         2

/* Total number of node table entries on PRU site */
#define NODE_TABLE_SIZE_MAX_TOTAL \
	(NODE_TABLE_SIZE_MAX + NODE_TABLE_NARROW_ENTRIES)

#define DUPLICATE_PORT_TABLE_DMEM_SIZE        0x0C00
#define NODE_TABLE_DMEM_SIZE                  0x1040
#define NEXT_FREE_ADDRESS_NT_QUEUE_DMEM_SIZE  NODE_TABLE_SIZE_MAX
#define DUPLICATE_HOST_TABLE_DMEM_SIZE        0x1800
#define BAD_FRAME_QUEUE_DMEM_SIZE             0x0080
#define LRE_STATS_DMEM_SIZE_HSR               0x0064
#define LRE_STATS_DMEM_SIZE                   0x0070
#define DEBUG_COUNTER_DMEM_SIZE               0x0050

/* PRU takes 1 Node Table entry to handle incoming frame */
#define NODE_TABLE_SIZE_MAX_PRU_INIT          (NODE_TABLE_SIZE_MAX - 1)

#define INDEX_ARRAY_INIT                       0x00008100

#define DUPLICATE_HOST_TABLE_SIZE_INIT         0x00800004  /* N = 128, M = 4 */
#define DUPLICATE_PORT_TABLE_SIZE_INIT         0x00400004  /* N = 64, M = 4 */
#define MASTER_SLAVE_BUSY_BITS_CLEAR           0x00000000
#define TABLE_CHECK_RESOLUTION_10_MS           0x0000000A
#define TIME_TIC_INC_PRU                       1 /* time tick according to
						  * resolution Time in TimeTicks
						  * (1/100s)
						  */
#define SUP_ADDRESS_INIT_OCTETS_HIGH           0x004E1501  /* 01-15-4E-00- */
#define SUP_ADDRESS_INIT_OCTETS_LOW            0x00000001  /* -01-00 */

/* SHARED RAM */

/* 8 bytes of VLAN PCP to RX QUEUE MAPPING */
#define QUEUE_2_PCP_MAP_OFFSET                 0x120
/* Value is always 0 and is used as lreInterfaceStatsIndex.
 * Starts after PTP.
 */
#define LRE_Interface_Stats_and_Monitoring     0x140
#define LRE_START                              0x140
/* Number of frames successfully sent over port A/B that are HSR/PRP tagged */
#define LRE_CNT_TX_A                           (LRE_START + 4)
#define LRE_CNT_TX_B                           (LRE_START + 8)
/* Number of frames sent successfully towards the application
 * interface of the DANH. Frames with and without PRP/HSR tag are counted
 */
#define LRE_CNT_TX_C                           (LRE_START + 12)
/* Number of frames with the wrong LAN identifier received on LRE port A/B/C */
#define LRE_CNT_ERRWRONGLAN_A                  (LRE_START + 16)
#define LRE_CNT_ERRWRONGLAN_B                  (LRE_START + 20)
#define LRE_CNT_ERRWRONGLAN_C                  (LRE_START + 24)
/* Number of frames received successfully with HSR or PRP TAG
 * on a LRE port A/B/C
 */
#define LRE_CNT_RX_A                           (LRE_START + 28)
#define LRE_CNT_RX_B                           (LRE_START + 32)
#define LRE_CNT_RX_C                           (LRE_START + 36)
/* Number of frames with errors received on this LRE port A/B/C */
#define LRE_CNT_ERRORS_A                       (LRE_START + 40)
#define LRE_CNT_ERRORS_B                       (LRE_START + 44)
#define LRE_CNT_ERRORS_C                       (LRE_START + 48)
/* Number of active nodes in the node table */
#define LRE_CNT_NODES                          (LRE_START + 52)
#define LRE_CNT_PROXY_NODES                    (LRE_START + 56)
/* Number of entries in the duplicate detection mechanism on
 * port A/B/C for which no duplicate was received.
 */
#define LRE_CNT_UNIQUE_RX_A                    (LRE_START + 60)
#define LRE_CNT_UNIQUE_RX_B                    (LRE_START + 64)
#define LRE_CNT_UNIQUE_RX_C                    (LRE_START + 68)
/* Number of entries in the duplicate detection mechanism on
 * port A/B/C for which one single duplicate was received
 */
#define LRE_CNT_DUPLICATE_RX_A                 (LRE_START + 72)
#define LRE_CNT_DUPLICATE_RX_B                 (LRE_START + 76)
#define LRE_CNT_DUPLICATE_RX_C                 (LRE_START + 80)

/* Number of entries in the duplicate detection mechanism on
 * port A/B/C for which more than one duplicate was received
 */
#define LRE_CNT_MULTIPLE_RX_A                  (LRE_START + 84)
#define LRE_CNT_MULTIPLE_RX_B                  (LRE_START + 88)
#define LRE_CNT_MULTIPLE_RX_C                  (LRE_START + 92)
/* Number of HSR tagged frames received on Port A/B that
 * originated from this device. Frames originate from this
 * device if the source MAC matches the MAC of the LRE (HSR ONLY)
 */
#define LRE_CNT_OWN_RX_A                       (LRE_START + 96)
#define LRE_CNT_OWN_RX_B                       (LRE_START + 100)

#define LRE_DUPLICATE_DISCARD                  (LRE_START + 104)
#define LRE_TRANSPARENT_RECEPTION              (LRE_START + 108)
#define LRE_NODE_TABLE_LOOKUP_ERROR_A          (LRE_START + 112)
#define LRE_NODE_TABLE_LOOKUP_ERROR_B          (LRE_START + 116)
#define LRE_NODE_TABLE_FULL                    (LRE_START + 120)
#define LRE_TOTAL_RX_A                         (LRE_START + 124)
#define LRE_TOTAL_RX_B                         (LRE_START + 128)
#define LRE_OVERFLOW_PRU0                      (LRE_START + 132)
#define LRE_OVERFLOW_PRU1                      (LRE_START + 136)
#define LRE_DD_PRU0                            (LRE_START + 140)
#define LRE_DD_PRU1                            (LRE_START + 144)
#define LRE_CNT_SUP_PRU0                       (LRE_START + 148)
#define LRE_CNT_SUP_PRU1                       (LRE_START + 152)

#define IEC62439_CONST_DUPLICATE_ACCEPT                 0x01
#define IEC62439_CONST_DUPLICATE_DISCARD                0x02
#define IEC62439_CONST_TRANSPARENT_RECEPTION_REMOVE_RCT 0x01
#define IEC62439_CONST_TRANSPARENT_RECEPTION_PASS_RCT   0x02

/* Index array : contiguous 1 byte size entries
 * (max 128 entries + 2 guard values at 0x1E0 (first byte)
 * and 0x262 (last byte)
 */
#define INDEX_ARRAY                       0x1E0
#define INDEX_ARRAY_END                   0x262
#define INDEX_ARRAY_CONTROLLER            0x270

/* Node Table: Max 128 entries + 2 guard values. Starts and ends with
 * a guard value
 */
#define NODE_TABLE                        0x1FC0
#define NODE_TABLE_FIRST_ENTRY            0x1FE0 /* 1st ent not count guard */
#define NODE_TABLE_LAST_ENTRY             0x2fC0 /* last not count guard */
#define NODE_TABLE_END                    0x2fE0

#define NODE_TABLE_NEW			  0x3000

#define NT_REM_NODE_TYPE_MASK     0x1F
#define NT_REM_NODE_TYPE_SHIFT    0x00

#define NT_REM_NODE_TYPE_SANA     0x01
#define NT_REM_NODE_TYPE_SANB     0x02
#define NT_REM_NODE_TYPE_SANAB    0x03
#define NT_REM_NODE_TYPE_DAN      0x04
#define NT_REM_NODE_TYPE_REDBOX   0x08
#define NT_REM_NODE_TYPE_VDAN     0x10

#define NT_REM_NODE_HSR_BIT       0x20 /* if set node is HSR */

#define NT_REM_NODE_DUP_MASK      0xC0
#define NT_REM_NODE_DUP_SHIFT     0x06

#define NT_REM_NODE_DUP_ACCEPT    0x40 /* Node ent duplicate type: DupAccept */
#define NT_REM_NODE_DUP_DISCARD   0x80 /* Node ent duplicate type: DupDiscard */

/* HOST_TIMER_CHECK_FLAGS bits */
#define HOST_TIMER_NODE_TABLE_CHECK_BIT    BIT(0)
#define HOST_TIMER_NODE_TABLE_CLEAR_BIT    BIT(4)
#define HOST_TIMER_HOST_TABLE_CHECK_BIT    BIT(8)
#define HOST_TIMER_P1_TABLE_CHECK_BIT      BIT(16)
#define HOST_TIMER_P2_TABLE_CHECK_BIT      BIT(24)
#define HOST_TIMER_PORT_TABLE_CHECK_BITS \
	(HOST_TIMER_P1_TABLE_CHECK_BIT | HOST_TIMER_P2_TABLE_CHECK_BIT)

#endif /* __ICSS_SWITCH_HSR_PRP_H */
