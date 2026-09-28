#!/usr/bin/env python3
"""Decode and diff firmware 'counters' snapshots (AmiNetXDuo #89).

  wlcnt.py show  DUMP                 every field of one snapshot
  wlcnt.py delta PRE POST [--all]     RX-side deltas between two snapshots
                                      (--all: every field in the layout)

DUMP is what tools/wlcntdump.c writes from a driver built with
-DWIFIPI_WLCNT: struct WcDumpHeader (src/wlcnt.h, big-endian), then the
firmware's 'counters' answer as it came (little-endian).

Output is key=value, one fact a line.  Exit 0 decoded, 2 refused (a line
refused=<reason>, then the answer's first bytes as hex.OFFSET= lines),
1 usage or file error.

Only layouts with a table below are read; any other version, a v10 length
without a table, a short answer or a malformed XTLV is refused, and no
offset is ever guessed.

  legacy v10 (u16 version = 10, u16 length = whole struct):
    length 848  WHD wl_cnt_ver_ten_t
                github.com/Infineon/wifi-host-driver bd99da7b,
                WHD/COMPONENT_WIFI6/src/include/whd_wlioctl.h:2961-3215;
                the same 848 bytes, field for field, are the head of bcmdhd's
                wl_cnt_ver_11_t (android.googlesource.com/kernel/google-modules/
                wlan/bcmdhd/bcm4389, android-gs-bluejay-5.10-android14
                6de00734, include/wlioctl.h:6352-6653; bcm_app_utils.c
                wl_cntbuf_to_xtlv_format() reads a v10 answer by that layout)
    length 844  the same without rxrtry: bcmdhd wl_cnt_t with
                WL_CNT_T_VERSION 10 (wlioctl.h 475499 2014-05-06,
                github.com/CyanogenMod/android_kernel_samsung_jf fbf391fe,
                drivers/net/wireless/bcmdhd/include/wlioctl.h:1576-1830)
  XTLV (u16 version = 30 WL_CNT_VERSION_XTLV, u16 datalen = bytes after the
  4-byte header; wl_cnt_info_t), then bcm_xtlv_t tuples: u16 id, u16 len,
  data, each padded to 4 (BCM_XTLV_OPTION_ALIGN32; bcm4389 bcmxtlv.c:63):
    0x100 WL_CNT_XTLV_WLC           wl_cnt_wlc_t, read as far as len goes
                                    (bcm4389 wlioctl.h:4892-5134, 864 bytes;
                                    WHD's 772-byte whd_wlioctl.h:1997-2214
                                    and Cypress bcmdhd's 732-byte
                                    wlioctl.h:2113-2316 are its head, field
                                    for field)
    0x200 WL_CNT_XTLV_CNTV_LE10_UCODE  wl_cnt_v_le10_mcst_t, 256 bytes exactly
    0x300 WL_CNT_XTLV_LT40_UCODE_V1    wl_cnt_lt40mcst_v1_t, 256 bytes exactly
    0x400 WL_CNT_XTLV_GE40_UCODE_V1    wl_cnt_ge40mcst_v1_t, 256 bytes exactly
    (bcm4389 wlioctl.h:4483-4518, 4829-4837, 5472-5650, 6255-6340; the same in
    Cypress bcmdhd wlioctl.h 688469 2018-04-20, github.com/yodaos-project/
    yodaos d0d7bbc2, hardware/wifi/bcmdhd_cypress/driver/include/wlioctl.h:
    2068-2081, 2102-2110, 2329-2583)
    any other id is listed as skipped, not read.

A delta is (post - pre) mod 2^32; post < pre is flagged wrap.NAME=1 (a u32
wrap and a firmware counter reset look the same).
"""
import struct
import sys

# ---------------------------------------------------------------------------
# Offset tables: (name, byte offset, width).  Arrays are expanded (rxuflo_0..5),
# padding kept (pad_OFFSET) so every table is contiguous; _check() proves that
# at import and that each ends at the documented struct size.
V10_FIELDS = (
    ('version', 0, 2), ('length', 2, 2), ('txframe', 4, 4), ('txbyte', 8, 4), ('txretrans', 12, 4),
    ('txerror', 16, 4), ('txctl', 20, 4), ('txprshort', 24, 4), ('txserr', 28, 4),
    ('txnobuf', 32, 4), ('txnoassoc', 36, 4), ('txrunt', 40, 4), ('txchit', 44, 4),
    ('txcmiss', 48, 4), ('txuflo', 52, 4), ('txphyerr', 56, 4), ('txphycrs', 60, 4),
    ('rxframe', 64, 4), ('rxbyte', 68, 4), ('rxerror', 72, 4), ('rxctl', 76, 4), ('rxnobuf', 80, 4),
    ('rxnondata', 84, 4), ('rxbadds', 88, 4), ('rxbadcm', 92, 4), ('rxfragerr', 96, 4),
    ('rxrunt', 100, 4), ('rxgiant', 104, 4), ('rxnoscb', 108, 4), ('rxbadproto', 112, 4),
    ('rxbadsrcmac', 116, 4), ('rxbadda', 120, 4), ('rxfilter', 124, 4), ('rxoflo', 128, 4),
    ('rxuflo_0', 132, 4), ('rxuflo_1', 136, 4), ('rxuflo_2', 140, 4), ('rxuflo_3', 144, 4),
    ('rxuflo_4', 148, 4), ('rxuflo_5', 152, 4), ('d11cnt_txrts_off', 156, 4),
    ('d11cnt_rxcrc_off', 160, 4), ('d11cnt_txnocts_off', 164, 4), ('dmade', 168, 4),
    ('dmada', 172, 4), ('dmape', 176, 4), ('reset', 180, 4), ('tbtt', 184, 4), ('txdmawar', 188, 4),
    ('pkt_callback_reg_fail', 192, 4), ('txallfrm', 196, 4), ('txrtsfrm', 200, 4),
    ('txctsfrm', 204, 4), ('txackfrm', 208, 4), ('txdnlfrm', 212, 4), ('txbcnfrm', 216, 4),
    ('txfunfl_0', 220, 4), ('txfunfl_1', 224, 4), ('txfunfl_2', 228, 4), ('txfunfl_3', 232, 4),
    ('txfunfl_4', 236, 4), ('txfunfl_5', 240, 4), ('rxtoolate', 244, 4), ('txfbw', 248, 4),
    ('txtplunfl', 252, 4), ('txphyerror', 256, 4), ('rxfrmtoolong', 260, 4),
    ('rxfrmtooshrt', 264, 4), ('rxinvmachdr', 268, 4), ('rxbadfcs', 272, 4), ('rxbadplcp', 276, 4),
    ('rxcrsglitch', 280, 4), ('rxstrt', 284, 4), ('rxdfrmucastmbss', 288, 4),
    ('rxmfrmucastmbss', 292, 4), ('rxcfrmucast', 296, 4), ('rxrtsucast', 300, 4),
    ('rxctsucast', 304, 4), ('rxackucast', 308, 4), ('rxdfrmocast', 312, 4),
    ('rxmfrmocast', 316, 4), ('rxcfrmocast', 320, 4), ('rxrtsocast', 324, 4),
    ('rxctsocast', 328, 4), ('rxdfrmmcast', 332, 4), ('rxmfrmmcast', 336, 4),
    ('rxcfrmmcast', 340, 4), ('rxbeaconmbss', 344, 4), ('rxdfrmucastobss', 348, 4),
    ('rxbeaconobss', 352, 4), ('rxrsptmout', 356, 4), ('bcntxcancl', 360, 4), ('rxf0ovfl', 364, 4),
    ('rxf1ovfl', 368, 4), ('rxf2ovfl', 372, 4), ('txsfovfl', 376, 4), ('pmqovfl', 380, 4),
    ('rxcgprqfrm', 384, 4), ('rxcgprsqovfl', 388, 4), ('txcgprsfail', 392, 4),
    ('txcgprssuc', 396, 4), ('prs_timeout', 400, 4), ('rxnack', 404, 4), ('frmscons', 408, 4),
    ('txnack', 412, 4), ('rxback', 416, 4), ('txback', 420, 4), ('txfrag', 424, 4),
    ('txmulti', 428, 4), ('txfail', 432, 4), ('txretry', 436, 4), ('txretrie', 440, 4),
    ('rxdup', 444, 4), ('txrts', 448, 4), ('txnocts', 452, 4), ('txnoack', 456, 4),
    ('rxfrag', 460, 4), ('rxmulti', 464, 4), ('rxcrc', 468, 4), ('txfrmsnt', 472, 4),
    ('rxundec', 476, 4), ('tkipmicfaill', 480, 4), ('tkipcntrmsr', 484, 4), ('tkipreplay', 488, 4),
    ('ccmpfmterr', 492, 4), ('ccmpreplay', 496, 4), ('ccmpundec', 500, 4), ('fourwayfail', 504, 4),
    ('wepundec', 508, 4), ('wepicverr', 512, 4), ('decsuccess', 516, 4), ('tkipicverr', 520, 4),
    ('wepexcluded', 524, 4), ('txchanrej', 528, 4), ('psmwds', 532, 4), ('phywatchdog', 536, 4),
    ('prq_entries_handled', 540, 4), ('prq_undirected_entries', 544, 4),
    ('prq_bad_entries', 548, 4), ('atim_suppress_count', 552, 4),
    ('bcn_template_not_ready', 556, 4), ('bcn_template_not_ready_done', 560, 4),
    ('late_tbtt_dpc', 564, 4), ('rx1mbps', 568, 4), ('rx2mbps', 572, 4), ('rx5mbps5', 576, 4),
    ('rx6mbps', 580, 4), ('rx9mbps', 584, 4), ('rx11mbps', 588, 4), ('rx12mbps', 592, 4),
    ('rx18mbps', 596, 4), ('rx24mbps', 600, 4), ('rx36mbps', 604, 4), ('rx48mbps', 608, 4),
    ('rx54mbps', 612, 4), ('rx108mbps', 616, 4), ('rx162mbps', 620, 4), ('rx216mbps', 624, 4),
    ('rx270mbps', 628, 4), ('rx324mbps', 632, 4), ('rx378mbps', 636, 4), ('rx432mbps', 640, 4),
    ('rx486mbps', 644, 4), ('rx540mbps', 648, 4), ('pktengrxducast', 652, 4),
    ('pktengrxdmcast', 656, 4), ('rfdisable', 660, 4), ('bphy_rxcrsglitch', 664, 4),
    ('bphy_badplcp', 668, 4), ('txexptime', 672, 4), ('txmpdu_sgi', 676, 4), ('rxmpdu_sgi', 680, 4),
    ('txmpdu_stbc', 684, 4), ('rxmpdu_stbc', 688, 4), ('rxundec_mcst', 692, 4),
    ('tkipmicfaill_mcst', 696, 4), ('tkipcntrmsr_mcst', 700, 4), ('tkipreplay_mcst', 704, 4),
    ('ccmpfmterr_mcst', 708, 4), ('ccmpreplay_mcst', 712, 4), ('ccmpundec_mcst', 716, 4),
    ('fourwayfail_mcst', 720, 4), ('wepundec_mcst', 724, 4), ('wepicverr_mcst', 728, 4),
    ('decsuccess_mcst', 732, 4), ('tkipicverr_mcst', 736, 4), ('wepexcluded_mcst', 740, 4),
    ('dma_hang', 744, 4), ('reinit', 748, 4), ('pstatxucast', 752, 4), ('pstatxnoassoc', 756, 4),
    ('pstarxucast', 760, 4), ('pstarxbcmc', 764, 4), ('pstatxbcmc', 768, 4),
    ('cso_passthrough', 772, 4), ('cso_normal', 776, 4), ('chained', 780, 4),
    ('chainedsz1', 784, 4), ('unchained', 788, 4), ('maxchainsz', 792, 4), ('currchainsz', 796, 4),
    ('rxdrop20s', 800, 4), ('pciereset', 804, 4), ('cfgrestore', 808, 4),
    ('reinitreason_0', 812, 4), ('reinitreason_1', 816, 4), ('reinitreason_2', 820, 4),
    ('reinitreason_3', 824, 4), ('reinitreason_4', 828, 4), ('reinitreason_5', 832, 4),
    ('reinitreason_6', 836, 4), ('reinitreason_7', 840, 4), ('rxrtry', 844, 4),
)
V10_FIELDS_SIZE = 848

WLC_FIELDS = (
    ('txframe', 0, 4), ('txbyte', 4, 4), ('txretrans', 8, 4), ('txerror', 12, 4), ('txctl', 16, 4),
    ('txprshort', 20, 4), ('txserr', 24, 4), ('txnobuf', 28, 4), ('txnoassoc', 32, 4),
    ('txrunt', 36, 4), ('txchit', 40, 4), ('txcmiss', 44, 4), ('txuflo', 48, 4),
    ('txphyerr', 52, 4), ('txphycrs', 56, 4), ('rxframe', 60, 4), ('rxbyte', 64, 4),
    ('rxerror', 68, 4), ('rxctl', 72, 4), ('rxnobuf', 76, 4), ('rxnondata', 80, 4),
    ('rxbadds', 84, 4), ('rxbadcm', 88, 4), ('rxfragerr', 92, 4), ('rxrunt', 96, 4),
    ('rxgiant', 100, 4), ('rxnoscb', 104, 4), ('rxbadproto', 108, 4), ('rxbadsrcmac', 112, 4),
    ('rxbadda', 116, 4), ('rxfilter', 120, 4), ('rxoflo', 124, 4), ('rxuflo_0', 128, 4),
    ('rxuflo_1', 132, 4), ('rxuflo_2', 136, 4), ('rxuflo_3', 140, 4), ('rxuflo_4', 144, 4),
    ('rxuflo_5', 148, 4), ('d11cnt_txrts_off', 152, 4), ('d11cnt_rxcrc_off', 156, 4),
    ('d11cnt_txnocts_off', 160, 4), ('dmade', 164, 4), ('dmada', 168, 4), ('dmape', 172, 4),
    ('reset', 176, 4), ('tbtt', 180, 4), ('txdmawar', 184, 4), ('pkt_callback_reg_fail', 188, 4),
    ('txfrag', 192, 4), ('txmulti', 196, 4), ('txfail', 200, 4), ('txretry', 204, 4),
    ('txretrie', 208, 4), ('rxdup', 212, 4), ('txrts', 216, 4), ('txnocts', 220, 4),
    ('txnoack', 224, 4), ('rxfrag', 228, 4), ('rxmulti', 232, 4), ('rxcrc', 236, 4),
    ('txfrmsnt', 240, 4), ('rxundec', 244, 4), ('tkipmicfaill', 248, 4), ('tkipcntrmsr', 252, 4),
    ('tkipreplay', 256, 4), ('ccmpfmterr', 260, 4), ('ccmpreplay', 264, 4), ('ccmpundec', 268, 4),
    ('fourwayfail', 272, 4), ('wepundec', 276, 4), ('wepicverr', 280, 4), ('decsuccess', 284, 4),
    ('tkipicverr', 288, 4), ('wepexcluded', 292, 4), ('txchanrej', 296, 4), ('psmwds', 300, 4),
    ('phywatchdog', 304, 4), ('prq_entries_handled', 308, 4), ('prq_undirected_entries', 312, 4),
    ('prq_bad_entries', 316, 4), ('atim_suppress_count', 320, 4),
    ('bcn_template_not_ready', 324, 4), ('bcn_template_not_ready_done', 328, 4),
    ('late_tbtt_dpc', 332, 4), ('rx1mbps', 336, 4), ('rx2mbps', 340, 4), ('rx5mbps5', 344, 4),
    ('rx6mbps', 348, 4), ('rx9mbps', 352, 4), ('rx11mbps', 356, 4), ('rx12mbps', 360, 4),
    ('rx18mbps', 364, 4), ('rx24mbps', 368, 4), ('rx36mbps', 372, 4), ('rx48mbps', 376, 4),
    ('rx54mbps', 380, 4), ('rx108mbps', 384, 4), ('rx162mbps', 388, 4), ('rx216mbps', 392, 4),
    ('rx270mbps', 396, 4), ('rx324mbps', 400, 4), ('rx378mbps', 404, 4), ('rx432mbps', 408, 4),
    ('rx486mbps', 412, 4), ('rx540mbps', 416, 4), ('rfdisable', 420, 4), ('txexptime', 424, 4),
    ('txmpdu_sgi', 428, 4), ('rxmpdu_sgi', 432, 4), ('txmpdu_stbc', 436, 4),
    ('rxmpdu_stbc', 440, 4), ('rxundec_mcst', 444, 4), ('tkipmicfaill_mcst', 448, 4),
    ('tkipcntrmsr_mcst', 452, 4), ('tkipreplay_mcst', 456, 4), ('ccmpfmterr_mcst', 460, 4),
    ('ccmpreplay_mcst', 464, 4), ('ccmpundec_mcst', 468, 4), ('fourwayfail_mcst', 472, 4),
    ('wepundec_mcst', 476, 4), ('wepicverr_mcst', 480, 4), ('decsuccess_mcst', 484, 4),
    ('tkipicverr_mcst', 488, 4), ('wepexcluded_mcst', 492, 4), ('dma_hang', 496, 4),
    ('reinit', 500, 4), ('pstatxucast', 504, 4), ('pstatxnoassoc', 508, 4), ('pstarxucast', 512, 4),
    ('pstarxbcmc', 516, 4), ('pstatxbcmc', 520, 4), ('cso_passthrough', 524, 4),
    ('cso_normal', 528, 4), ('chained', 532, 4), ('chainedsz1', 536, 4), ('unchained', 540, 4),
    ('maxchainsz', 544, 4), ('currchainsz', 548, 4), ('pciereset', 552, 4), ('cfgrestore', 556, 4),
    ('reinitreason_0', 560, 4), ('reinitreason_1', 564, 4), ('reinitreason_2', 568, 4),
    ('reinitreason_3', 572, 4), ('reinitreason_4', 576, 4), ('reinitreason_5', 580, 4),
    ('reinitreason_6', 584, 4), ('reinitreason_7', 588, 4), ('rxrtry', 592, 4),
    ('rxmpdu_mu', 596, 4), ('txbar', 600, 4), ('rxbar', 604, 4), ('txpspoll', 608, 4),
    ('rxpspoll', 612, 4), ('txnull', 616, 4), ('rxnull', 620, 4), ('txqosnull', 624, 4),
    ('rxqosnull', 628, 4), ('txassocreq', 632, 4), ('rxassocreq', 636, 4), ('txreassocreq', 640, 4),
    ('rxreassocreq', 644, 4), ('txdisassoc', 648, 4), ('rxdisassoc', 652, 4),
    ('txassocrsp', 656, 4), ('rxassocrsp', 660, 4), ('txreassocrsp', 664, 4),
    ('rxreassocrsp', 668, 4), ('txauth', 672, 4), ('rxauth', 676, 4), ('txdeauth', 680, 4),
    ('rxdeauth', 684, 4), ('txprobereq', 688, 4), ('rxprobereq', 692, 4), ('txprobersp', 696, 4),
    ('rxprobersp', 700, 4), ('txaction', 704, 4), ('rxaction', 708, 4), ('ampdu_wds', 712, 4),
    ('txlost', 716, 4), ('txdatamcast', 720, 4), ('txdatabcast', 724, 4), ('psmxwds', 728, 4),
    ('rxback', 732, 4), ('txback', 736, 4), ('p2p_tbtt', 740, 4), ('p2p_tbtt_miss', 744, 4),
    ('txqueue_start', 748, 4), ('txqueue_end', 752, 4), ('txbcast', 756, 4), ('txdropped', 760, 4),
    ('rxbcast', 764, 4), ('rxdropped', 768, 4), ('txq_end_assoccb', 772, 4),
    ('tx_toss_cnt', 776, 4), ('rx_toss_cnt', 780, 4), ('last_tx_toss_rsn', 784, 4),
    ('last_rx_toss_rsn', 788, 4), ('pmk_badlen_cnt', 792, 4), ('txbar_notx', 796, 4),
    ('txbar_noack', 800, 4), ('rxfrag_agedout', 804, 4), ('pmkid_mismatch_cnt', 808, 4),
    ('txaction_vndr_attempt', 812, 4), ('txaction_vndr_fail', 816, 4), ('rxnofrag', 820, 4),
    ('rxnocmplid', 824, 4), ('rxnohaddr', 828, 4), ('txnull_pm', 832, 4),
    ('txnull_pm_succ', 836, 4), ('ccmpreplay_qosdata_nobapol_rxretry', 840, 4),
    ('txnoalfdatabuf', 844, 4), ('txalfdatabuf', 848, 4), ('txalfrag', 852, 4), ('txlfrag', 856, 4),
    ('rxunsolicitedproberesp', 860, 4),
)
WLC_FIELDS_SIZE = 864

GE40_FIELDS = (
    ('txallfrm', 0, 4), ('txrtsfrm', 4, 4), ('txctsfrm', 8, 4), ('txackfrm', 12, 4),
    ('txdnlfrm', 16, 4), ('txbcnfrm', 20, 4), ('txfunfl_0', 24, 4), ('txfunfl_1', 28, 4),
    ('txfunfl_2', 32, 4), ('txfunfl_3', 36, 4), ('txfunfl_4', 40, 4), ('txfunfl_5', 44, 4),
    ('txampdu', 48, 4), ('txmpdu', 52, 4), ('txtplunfl', 56, 4), ('txphyerror', 60, 4),
    ('pktengrxducast', 64, 4), ('pktengrxdmcast', 68, 4), ('rxfrmtoolong', 72, 4),
    ('rxfrmtooshrt', 76, 4), ('rxanyerr', 80, 4), ('rxbadfcs', 84, 4), ('rxbadplcp', 88, 4),
    ('rxcrsglitch', 92, 4), ('rxstrt', 96, 4), ('rxdtucastmbss', 100, 4), ('rxmgucastmbss', 104, 4),
    ('rxctlucast', 108, 4), ('rxrtsucast', 112, 4), ('rxctsucast', 116, 4), ('rxackucast', 120, 4),
    ('rxdtocast', 124, 4), ('rxmgocast', 128, 4), ('rxctlocast', 132, 4), ('rxrtsocast', 136, 4),
    ('rxctsocast', 140, 4), ('rxdtmcast', 144, 4), ('rxmgmcast', 148, 4), ('rxctlmcast', 152, 4),
    ('rxbeaconmbss', 156, 4), ('rxdtucastobss', 160, 4), ('rxbeaconobss', 164, 4),
    ('rxrsptmout', 168, 4), ('bcntxcancl', 172, 4), ('rxnodelim', 176, 4), ('rxf0ovfl', 180, 4),
    ('rxf1ovfl', 184, 4), ('rxhlovfl', 188, 4), ('missbcn_dbg', 192, 4), ('pmqovfl', 196, 4),
    ('rxcgprqfrm', 200, 4), ('rxcgprsqovfl', 204, 4), ('txcgprsfail', 208, 4),
    ('txcgprssuc', 212, 4), ('prs_timeout', 216, 4), ('txrtsfail', 220, 4), ('txucast', 224, 4),
    ('txinrtstxop', 228, 4), ('rxback', 232, 4), ('txback', 236, 4), ('bphy_rxcrsglitch', 240, 4),
    ('rxdrop20s', 244, 4), ('rxtoolate', 248, 4), ('bphy_badplcp', 252, 4),
)
GE40_FIELDS_SIZE = 256

LT40_FIELDS = (
    ('txallfrm', 0, 4), ('txrtsfrm', 4, 4), ('txctsfrm', 8, 4), ('txackfrm', 12, 4),
    ('txdnlfrm', 16, 4), ('txbcnfrm', 20, 4), ('txfunfl_0', 24, 4), ('txfunfl_1', 28, 4),
    ('txfunfl_2', 32, 4), ('txfunfl_3', 36, 4), ('txfunfl_4', 40, 4), ('txfunfl_5', 44, 4),
    ('txampdu', 48, 4), ('txmpdu', 52, 4), ('txtplunfl', 56, 4), ('txphyerror', 60, 4),
    ('pktengrxducast', 64, 4), ('pktengrxdmcast', 68, 4), ('rxfrmtoolong', 72, 4),
    ('rxfrmtooshrt', 76, 4), ('rxanyerr', 80, 4), ('rxbadfcs', 84, 4), ('rxbadplcp', 88, 4),
    ('rxcrsglitch', 92, 4), ('rxstrt', 96, 4), ('rxdtucastmbss', 100, 4), ('rxmgucastmbss', 104, 4),
    ('rxctlucast', 108, 4), ('rxrtsucast', 112, 4), ('rxctsucast', 116, 4), ('rxackucast', 120, 4),
    ('rxdtocast', 124, 4), ('rxmgocast', 128, 4), ('rxctlocast', 132, 4), ('rxrtsocast', 136, 4),
    ('rxctsocast', 140, 4), ('rxdtmcast', 144, 4), ('rxmgmcast', 148, 4), ('rxctlmcast', 152, 4),
    ('rxbeaconmbss', 156, 4), ('rxdtucastobss', 160, 4), ('rxbeaconobss', 164, 4),
    ('rxrsptmout', 168, 4), ('bcntxcancl', 172, 4), ('rxnodelim', 176, 4), ('rxf0ovfl', 180, 4),
    ('dbgoff46', 184, 4), ('dbgoff47', 188, 4), ('dbgoff48', 192, 4), ('pmqovfl', 196, 4),
    ('rxcgprqfrm', 200, 4), ('rxcgprsqovfl', 204, 4), ('txcgprsfail', 208, 4),
    ('txcgprssuc', 212, 4), ('prs_timeout', 216, 4), ('txrtsfail', 220, 4), ('txucast', 224, 4),
    ('txinrtstxop', 228, 4), ('rxback', 232, 4), ('txback', 236, 4), ('bphy_rxcrsglitch', 240, 4),
    ('phywatch', 244, 4), ('rxtoolate', 248, 4), ('bphy_badplcp', 252, 4),
)
LT40_FIELDS_SIZE = 256

LE10_FIELDS = (
    ('txallfrm', 0, 4), ('txrtsfrm', 4, 4), ('txctsfrm', 8, 4), ('txackfrm', 12, 4),
    ('txdnlfrm', 16, 4), ('txbcnfrm', 20, 4), ('txfunfl_0', 24, 4), ('txfunfl_1', 28, 4),
    ('txfunfl_2', 32, 4), ('txfunfl_3', 36, 4), ('txfunfl_4', 40, 4), ('txfunfl_5', 44, 4),
    ('txfbw', 48, 4), ('pad_52', 52, 4), ('txtplunfl', 56, 4), ('txphyerror', 60, 4),
    ('pktengrxducast', 64, 4), ('pktengrxdmcast', 68, 4), ('rxfrmtoolong', 72, 4),
    ('rxfrmtooshrt', 76, 4), ('rxinvmachdr', 80, 4), ('rxbadfcs', 84, 4), ('rxbadplcp', 88, 4),
    ('rxcrsglitch', 92, 4), ('rxstrt', 96, 4), ('rxdfrmucastmbss', 100, 4),
    ('rxmfrmucastmbss', 104, 4), ('rxcfrmucast', 108, 4), ('rxrtsucast', 112, 4),
    ('rxctsucast', 116, 4), ('rxackucast', 120, 4), ('rxdfrmocast', 124, 4),
    ('rxmfrmocast', 128, 4), ('rxcfrmocast', 132, 4), ('rxrtsocast', 136, 4),
    ('rxctsocast', 140, 4), ('rxdfrmmcast', 144, 4), ('rxmfrmmcast', 148, 4),
    ('rxcfrmmcast', 152, 4), ('rxbeaconmbss', 156, 4), ('rxdfrmucastobss', 160, 4),
    ('rxbeaconobss', 164, 4), ('rxrsptmout', 168, 4), ('bcntxcancl', 172, 4), ('pad_176', 176, 4),
    ('rxf0ovfl', 180, 4), ('rxf1ovfl', 184, 4), ('rxf2ovfl', 188, 4), ('txsfovfl', 192, 4),
    ('pmqovfl', 196, 4), ('rxcgprqfrm', 200, 4), ('rxcgprsqovfl', 204, 4), ('txcgprsfail', 208, 4),
    ('txcgprssuc', 212, 4), ('prs_timeout', 216, 4), ('rxnack', 220, 4), ('frmscons', 224, 4),
    ('txnack', 228, 4), ('rxback', 232, 4), ('txback', 236, 4), ('bphy_rxcrsglitch', 240, 4),
    ('rxdrop20s', 244, 4), ('rxtoolate', 248, 4), ('bphy_badplcp', 252, 4),
)
LE10_FIELDS_SIZE = 256

V10_844_SIZE = 844                     # the 2014 v10: V10_FIELDS without rxrtry
MCST_SIZE = 256                        # WL_CNT_MCST_STRUCT_SZ: 64 u32

WC_DUMP_MAGIC = 0x574C4331             # src/wlcnt.h
WC_DUMP_VERSION = 1
WC_HEADER = struct.Struct(">IHHIIIIII")  # struct WcDumpHeader, 32 bytes
XTLV_VERSION = 30


def _check(fields, size):
    off = 0
    names = set()
    for name, o, w in fields:
        if o != off or w not in (2, 4) or name in names:
            raise AssertionError("table broken at %s" % name)
        names.add(name)
        off += w
    if off != size:
        raise AssertionError("table ends at %d, struct is %d" % (off, size))


_check(V10_FIELDS, V10_FIELDS_SIZE)
_check(WLC_FIELDS, WLC_FIELDS_SIZE)
_check(GE40_FIELDS, MCST_SIZE)
_check(LT40_FIELDS, MCST_SIZE)
_check(LE10_FIELDS, MCST_SIZE)
assert V10_FIELDS_SIZE == 848 and WLC_FIELDS_SIZE == 864
assert V10_FIELDS[-1][0] == "rxrtry" and V10_FIELDS[-1][1] == V10_844_SIZE

# (version, length) -> (layout, table); nothing else legacy is read
LEGACY = {
    (10, 848): ("v10_848", V10_FIELDS),
    (10, 844): ("v10_844", V10_FIELDS[:-1]),
}
MCST_IDS = {0x200: ("le10", LE10_FIELDS), 0x300: ("lt40", LT40_FIELDS), 0x400: ("ge40", GE40_FIELDS)}
WLC_ID = 0x100

# RX-side fields a delta prints, in this order.  Legacy v10 names:
RX_V10 = (
    "rxframe", "rxbyte", "rxerror", "rxctl", "rxnobuf", "rxnondata", "rxbadds", "rxbadcm",
    "rxfragerr", "rxrunt", "rxgiant", "rxnoscb", "rxbadproto", "rxbadsrcmac", "rxbadda",
    "rxfilter", "rxoflo", "rxuflo_0", "rxuflo_1", "rxuflo_2", "rxuflo_3", "rxuflo_4", "rxuflo_5",
    "dmade", "dmada", "dmape", "reset", "rxtoolate", "rxfrmtoolong", "rxfrmtooshrt", "rxinvmachdr",
    "rxbadfcs", "rxbadplcp", "rxcrsglitch", "rxstrt", "rxdfrmucastmbss", "rxmfrmucastmbss",
    "rxcfrmucast", "rxackucast", "rxdfrmocast", "rxdfrmmcast", "rxbeaconmbss", "rxbeaconobss",
    "rxrsptmout", "rxf0ovfl", "rxf1ovfl", "rxf2ovfl", "pmqovfl", "rxback", "rxdup", "rxfrag",
    "rxmulti", "rxcrc", "rxundec", "decsuccess", "tkipreplay", "ccmpreplay", "ccmpundec",
    "psmwds", "phywatchdog", "bphy_rxcrsglitch", "bphy_badplcp", "rxdrop20s", "dma_hang",
    "reinit", "rxrtry")
# ... of which a rise is RX error/drop evidence
RX_ERR_V10 = (
    "rxerror", "rxnobuf", "rxnondata", "rxbadds", "rxbadcm", "rxfragerr", "rxrunt", "rxgiant",
    "rxnoscb", "rxbadproto", "rxbadsrcmac", "rxbadda", "rxoflo", "rxuflo_0", "rxuflo_1",
    "rxuflo_2", "rxuflo_3", "rxuflo_4", "rxuflo_5", "dmade", "dmada", "dmape", "reset",
    "rxtoolate", "rxfrmtoolong", "rxfrmtooshrt", "rxinvmachdr", "rxbadfcs", "rxbadplcp",
    "rxf0ovfl", "rxf1ovfl", "rxf2ovfl", "pmqovfl", "rxcrc", "rxundec", "tkipreplay",
    "ccmpreplay", "ccmpundec", "psmwds", "phywatchdog", "bphy_badplcp", "rxdrop20s",
    "dma_hang", "reinit")
# XTLV: wlc.NAME from block 0x100, mcst.NAME from whichever MACSTAT block came
RX_XTLV = tuple("wlc." + n for n in (
    "rxframe", "rxbyte", "rxerror", "rxctl", "rxnobuf", "rxnondata", "rxbadds", "rxbadcm",
    "rxfragerr", "rxrunt", "rxgiant", "rxnoscb", "rxbadproto", "rxbadsrcmac", "rxbadda",
    "rxfilter", "rxoflo", "rxuflo_0", "rxuflo_1", "rxuflo_2", "rxuflo_3", "rxuflo_4", "rxuflo_5",
    "dmade", "dmada", "dmape", "reset", "rxdup", "rxfrag", "rxmulti", "rxcrc", "rxundec",
    "decsuccess", "tkipreplay", "ccmpreplay", "ccmpundec", "psmwds", "phywatchdog", "dma_hang",
    "reinit", "rxrtry")) + tuple("mcst." + n for n in (
    "rxfrmtoolong", "rxfrmtooshrt", "rxanyerr", "rxinvmachdr", "rxbadfcs", "rxbadplcp",
    "rxcrsglitch", "rxstrt", "rxdtucastmbss", "rxdfrmucastmbss", "rxackucast", "rxbeaconmbss",
    "rxbeaconobss", "rxrsptmout", "rxnodelim", "rxf0ovfl", "rxf1ovfl", "rxf2ovfl", "rxhlovfl",
    "pmqovfl", "rxback", "rxtoolate", "rxdrop20s", "bphy_rxcrsglitch", "bphy_badplcp"))
RX_ERR_XTLV = tuple("wlc." + n for n in (
    "rxerror", "rxnobuf", "rxnondata", "rxbadds", "rxbadcm", "rxfragerr", "rxrunt", "rxgiant",
    "rxnoscb", "rxbadproto", "rxbadsrcmac", "rxbadda", "rxoflo", "rxuflo_0", "rxuflo_1",
    "rxuflo_2", "rxuflo_3", "rxuflo_4", "rxuflo_5", "dmade", "dmada", "dmape", "reset", "rxcrc",
    "rxundec", "tkipreplay", "ccmpreplay", "ccmpundec", "psmwds", "phywatchdog", "dma_hang",
    "reinit")) + tuple("mcst." + n for n in (
    "rxfrmtoolong", "rxfrmtooshrt", "rxanyerr", "rxinvmachdr", "rxbadfcs", "rxbadplcp",
    "rxf0ovfl", "rxf1ovfl", "rxf2ovfl", "rxhlovfl", "pmqovfl", "rxtoolate", "rxdrop20s",
    "bphy_badplcp"))
assert set(RX_ERR_V10) <= set(RX_V10) and set(RX_ERR_XTLV) <= set(RX_XTLV)
assert set(RX_V10) <= set(n for n, _, _ in V10_FIELDS)
assert set(n[4:] for n in RX_XTLV if n.startswith("wlc.")) <= set(n for n, _, _ in WLC_FIELDS)
assert set(n[5:] for n in RX_XTLV if n.startswith("mcst.")) <= \
    set(n for t in MCST_IDS.values() for n, _, _ in t[1])


class Refused(Exception):
    def __init__(self, reason, data=b""):
        Exception.__init__(self, reason)
        self.reason = reason
        self.data = data


def hexlines(data, limit=256):
    out = []
    for o in range(0, min(len(data), limit), 16):
        out.append("hex.%04x=%s" % (o, " ".join("%02x" % c for c in data[o:o + 16])))
    return out


def _read(data, fields, prefix, upto):
    """Fields that lie wholly inside data[:upto]; nothing past it."""
    out = {}
    for name, off, w in fields:
        if name.startswith("pad_") or off + w > upto:
            continue
        out[prefix + name] = struct.unpack_from("<H" if w == 2 else "<I", data, off)[0]
    return out


def decode(data, copied):
    """(layout, {name: value}) or Refused.  data: the answer, copied: bytes of it that arrived."""
    if copied < 4 or copied > len(data):
        raise Refused("short answer: %d bytes arrived" % copied, data[:max(copied, 0)])
    ver, ln = struct.unpack_from("<HH", data, 0)
    if ver == XTLV_VERSION:
        return _decode_xtlv(data, copied, ln)
    if (ver, ln) not in LEGACY:
        known = ", ".join("v%d/%d" % k for k in sorted(LEGACY))
        raise Refused("no proven table for version %d length %d (read: %s, XTLV v%d)"
                      % (ver, ln, known, XTLV_VERSION), data[:copied])
    if ln > copied:
        raise Refused("short answer: version %d says %d bytes, %d arrived" % (ver, ln, copied),
                      data[:copied])
    layout, fields = LEGACY[(ver, ln)]
    vals = _read(data, fields, "", ln)
    del vals["version"], vals["length"]
    return layout, vals


def _decode_xtlv(data, copied, datalen):
    end = 4 + datalen
    if end > copied:
        raise Refused("short answer: XTLV datalen %d needs %d bytes, %d arrived"
                      % (datalen, end, copied), data[:copied])
    vals, blocks, pos = {}, [], 4
    while pos < end:
        if pos + 4 > end:
            raise Refused("XTLV header cut at %d" % pos, data[:copied])
        xid, xlen = struct.unpack_from("<HH", data, pos)
        size = (4 + xlen + 3) & ~3
        if pos + size > end:
            raise Refused("XTLV id 0x%x len %d runs past datalen %d" % (xid, xlen, datalen),
                          data[:copied])
        body = data[pos + 4:pos + 4 + xlen]
        if xid in [b[0] for b in blocks]:
            raise Refused("XTLV id 0x%x twice" % xid, data[:copied])
        if xid == WLC_ID:
            if xlen % 4 or xlen == 0:
                raise Refused("XTLV WLC len %d is not whole u32s" % xlen, data[:copied])
            vals.update(_read(body, WLC_FIELDS, "wlc.", xlen))
            blocks.append((xid, xlen, "wlc"))
        elif xid in MCST_IDS:
            kind, fields = MCST_IDS[xid]
            if xlen != MCST_SIZE:
                raise Refused("XTLV MACSTAT 0x%x len %d, table is %d" % (xid, xlen, MCST_SIZE),
                              data[:copied])
            if any(b[2].startswith("mcst") for b in blocks):
                raise Refused("two XTLV MACSTAT blocks", data[:copied])
            vals.update(_read(body, fields, "mcst.", xlen))
            blocks.append((xid, xlen, "mcst_" + kind))
        else:
            blocks.append((xid, xlen, "skipped"))
        pos += size
    if not any(b[2] != "skipped" for b in blocks):
        raise Refused("XTLV without a block this decoder has a table for", data[:copied])
    layout = "xtlv_v30:" + ",".join("0x%x/%d" % (i, n) for i, n, _ in blocks)
    return layout, vals


def load(path):
    """(header dict, answer bytes) of a wlcntdump file, or Refused."""
    b = open(path, "rb").read()
    if len(b) < WC_HEADER.size:
        raise Refused("%s: %d bytes, no header" % (path, len(b)), b)
    magic, ver, hsz, clo0, clo1, err, asked, copied, flags = WC_HEADER.unpack_from(b, 0)
    if magic != WC_DUMP_MAGIC or ver != WC_DUMP_VERSION or hsz != WC_HEADER.size:
        raise Refused("%s: not a wlcnt dump v%d" % (path, WC_DUMP_VERSION), b[:64])
    if len(b) != hsz + asked or copied > asked:
        raise Refused("%s: %d bytes, header says %d + %d (copied %d)"
                      % (path, len(b), hsz, asked, copied), b[:64])
    if err:
        raise Refused("%s: the GET failed, error 0x%08x" % (path, err), b[hsz:hsz + copied])
    h = {"clo_before": clo0, "clo_after": clo1, "asked": asked, "copied": copied,
         "unit_flags": flags}
    return h, b[hsz:]


def delta(pre, post):
    """{name: (delta mod 2^32, wrapped)} for names in both"""
    out = {}
    for k in pre:
        if k in post:
            out[k] = ((post[k] - pre[k]) & 0xFFFFFFFF, post[k] < pre[k])
    return out


def cmd_show(path):
    h, data = load(path)
    layout, vals = decode(data, h["copied"])
    out = ["layout=%s" % layout] + ["%s=%d" % kv for kv in sorted(h.items())]
    out += ["field.%s=%d" % kv for kv in vals.items()]
    return out


def cmd_delta(pre_path, post_path, every=False):
    h0, d0 = load(pre_path)
    h1, d1 = load(post_path)
    l0, v0 = decode(d0, h0["copied"])
    l1, v1 = decode(d1, h1["copied"])
    if l0 != l1:
        raise Refused("layouts differ: pre %s, post %s" % (l0, l1), d1[:h1["copied"]])
    legacy = not l0.startswith("xtlv")
    names = [k for k in v0] if every else list(RX_V10 if legacy else RX_XTLV)
    errs = RX_ERR_V10 if legacy else RX_ERR_XTLV
    d = delta(v0, v1)
    out = ["layout=%s" % l0,
           "pre.clo_after=%d" % h0["clo_after"], "post.clo_before=%d" % h1["clo_before"],
           "elapsed_us=%d" % ((h1["clo_before"] - h0["clo_after"]) & 0xFFFFFFFF),
           "fields=%s" % ",".join(names)]
    wrapped, rose = [], []
    for n in names:
        if n not in d:
            out.append("delta.%s=absent" % n)
            continue
        v, w = d[n]
        out.append("delta.%s=%d" % (n, v))
        if w:
            wrapped.append(n)
            out.append("wrap.%s=1" % n)
        if n in errs and v:
            rose.append(n)
    out.append("wrapped=%s" % (",".join(wrapped) or "none"))
    out.append("rx_error_fields=%s" % ",".join(e for e in errs if e in names))
    out.append("rx_errors_rose=%d" % (1 if rose else 0))
    out.append("rx_errors_rose_fields=%s" % (",".join(rose) or "none"))
    return out


def main(argv):
    try:
        if len(argv) == 2 and argv[0] == "show":
            out = cmd_show(argv[1])
        elif len(argv) in (3, 4) and argv[0] == "delta" and argv[3:] in ([], ["--all"]):
            out = cmd_delta(argv[1], argv[2], argv[3:] == ["--all"])
        else:
            print(__doc__.split("\n\n")[1], file=sys.stderr)
            return 1
    except Refused as r:
        print("refused=%s" % r.reason)
        for line in hexlines(r.data):
            print(line)
        return 2
    except OSError as e:
        print("error=%s" % e)
        return 1
    for line in out:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
