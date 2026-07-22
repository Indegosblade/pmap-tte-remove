# PMAP Patch Status Across All Chips
**Date:** 2026-03-27

### iPhone12,8_15.5_19F77_Restore
```
pmap_tte_remove strings:
pmap_tte_remove

Overflow/limit protection:
(ifp->if_mtu + ETHER_HDR_LEN) <= UINT16_MAX
ifp->if_mtu <= UINT16_MAX
ifp->if_tso_v4_mtu <= UINT16_MAX
ifp->if_tso_v6_mtu <= UINT16_MAX
m_pktlen(m) >= 0 && m_pktlen(m) < UINT16_MAX
```

### iPhone12,8_26.0_23A341_Restore
```
pmap_tte_remove strings:
pmap_tte_remove

Overflow/limit protection:
ifp->if_mtu <= UINT16_MAX
ifp->if_tso_v4_mtu <= UINT16_MAX
ifp->if_tso_v6_mtu <= UINT16_MAX
inp->inp_bind_in_progress_waiters != UINT16_MAX
m_pktlen(m) >= 0 && m_pktlen(m) < UINT16_MAX
```

### iPhone12,8_26.4_23E244_Restore
```
pmap_tte_remove strings:
pmap_tte_remove

Overflow/limit protection:
ifp->if_mtu <= UINT16_MAX
ifp->if_tso_v4_mtu <= UINT16_MAX
ifp->if_tso_v6_mtu <= UINT16_MAX
inp->inp_bind_in_progress_waiters != UINT16_MAX
m_pktlen(m) >= 0 && m_pktlen(m) < UINT16_MAX
```

### iPhone16,1_26.0_23A341_Restore
```
pmap_tte_remove strings:
pmap_tte_remove

Overflow/limit protection:
ifp->if_mtu <= UINT16_MAX
ifp->if_tso_v4_mtu <= UINT16_MAX
ifp->if_tso_v6_mtu <= UINT16_MAX
inp->inp_bind_in_progress_waiters != UINT16_MAX
m_pktlen(m) >= 0 && m_pktlen(m) < UINT16_MAX
```

### iPhone16,1_26.4_23E246_Restore
```
pmap_tte_remove strings:
pmap_tte_remove

Overflow/limit protection:
ifp->if_mtu <= UINT16_MAX
ifp->if_tso_v4_mtu <= UINT16_MAX
ifp->if_tso_v6_mtu <= UINT16_MAX
inp->inp_bind_in_progress_waiters != UINT16_MAX
m_pktlen(m) >= 0 && m_pktlen(m) < UINT16_MAX
```

### iPhone18,1_26.0_23A341_Restore
```
pmap_tte_remove strings:
pmap_tte_remove

Overflow/limit protection:
ifp->if_mtu <= UINT16_MAX
ifp->if_tso_v4_mtu <= UINT16_MAX
ifp->if_tso_v6_mtu <= UINT16_MAX
inp->inp_bind_in_progress_waiters != UINT16_MAX
m_pktlen(m) >= 0 && m_pktlen(m) < UINT16_MAX
```

### iPhone18,1_26.3.1_23D8133_Restore
```
pmap_tte_remove strings:
pmap_tte_remove

Overflow/limit protection:
ifp->if_mtu <= UINT16_MAX
ifp->if_tso_v4_mtu <= UINT16_MAX
ifp->if_tso_v6_mtu <= UINT16_MAX
inp->inp_bind_in_progress_waiters != UINT16_MAX
m_pktlen(m) >= 0 && m_pktlen(m) < UINT16_MAX
```

### iPhone18,1_26.4_23E246_Restore
```
pmap_tte_remove strings:
pmap_tte_remove

Overflow/limit protection:
ifp->if_mtu <= UINT16_MAX
ifp->if_tso_v4_mtu <= UINT16_MAX
ifp->if_tso_v6_mtu <= UINT16_MAX
inp->inp_bind_in_progress_waiters != UINT16_MAX
m_pktlen(m) >= 0 && m_pktlen(m) < UINT16_MAX
```

### iPhone18,3_26.4_23E246_Restore
```
pmap_tte_remove strings:
pmap_tte_remove

Overflow/limit protection:
ifp->if_mtu <= UINT16_MAX
ifp->if_tso_v4_mtu <= UINT16_MAX
ifp->if_tso_v6_mtu <= UINT16_MAX
inp->inp_bind_in_progress_waiters != UINT16_MAX
m_pktlen(m) >= 0 && m_pktlen(m) < UINT16_MAX
```

