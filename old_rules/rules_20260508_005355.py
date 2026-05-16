# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 08/05/2026 00:50:56
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_grayhole_low_sqnum(packet: dict) -> bool:
    """Detect low SqNum combined with unusually long time since last change."""
    sq = packet.get("SqNum", 0)
    tfd = packet.get("timeFromLastChange", 0)
    return (sq < 4.9) and (tfd > 100)

def rule_grayhole_low_stnum(packet: dict) -> bool:
    """Detect low StNum combined with an elevated processing delay."""
    st = packet.get("StNum", 0)
    d = packet.get("delay", 0)
    return (st < 173.9) and (d > 0.001)

def rule_grayhole_sqnum_stdiff(packet: dict) -> bool:
    """Detect low SqNum together with an abnormally positive state difference."""
    sq = packet.get("SqNum", 0)
    sd = packet.get("stDiff", 0)
    return (sq < 4.9) and (sd > 500)

def rule_high_StNum_state(packet: dict) -> bool:
    """Detect high StNum combined with large stDiff."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum > 1000) and (stdiff > 500)

def rule_high_StNum_seq(packet: dict) -> bool:
    """Detect inflated SqNum together with large sqDiff."""
    sqnum = packet.get("SqNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    return (sqnum > 50) and (sqdiff > 30)

def rule_high_StNum_time(packet: dict) -> bool:
    """Detect negative timeFromLastChange with stretched timestampDiff."""
    time_last = packet.get("timeFromLastChange", 0)
    tsdiff = packet.get("timestampDiff", 0)
    return (time_last < 0) and (tsdiff > 0.20)

def rule_high_StNum_misc(packet: dict) -> bool:
    """Detect extreme tDiff together with high StNum."""
    tdiff = packet.get("tDiff", 0)
    stnum = packet.get("StNum", 0)
    return (tdiff > 2500) and (stnum > 1000)

def rule_injection_seq_ts(packet: dict) -> bool:
    """Detect injection by unusually high sequence number combined with large timestamp difference."""
    sq_num = packet.get("SqNum", 0)
    timestamp_diff = packet.get("timestampDiff", 0)
    return (sq_num > 55) and (timestamp_diff > 0.5)

def rule_injection_state_status(packet: dict) -> bool:
    """Detect injection by low state number together with abnormal status bits."""
    st_num = packet.get("StNum", 0)
    cb_status = packet.get("cbStatus", 0)
    return (st_num < 174) and (cb_status > 1)

def rule_injection_timing_jump(packet: dict) -> bool:
    """Detect injection by extreme negative stDiff and a large jump in sequence number difference."""
    st_diff = packet.get("stDiff", 0)
    sq_diff = packet.get("sqDiff", 0)
    return (st_diff < -60000) and (sq_diff > 31)

def rule_injection_time_anomaly(packet: dict) -> bool:
    """Detect injection by strongly negative tDiff together with a negative timeFromLastChange."""
    t_diff = packet.get("tDiff", 0)
    time_from_last_change = packet.get("timeFromLastChange", 0)
    return (t_diff < -200) and (time_from_last_change < 0)

def rule_inverse_replay_seq_time(packet: dict) -> bool:
    """Detect low sequence number combined with large inter-frame time and long inactivity."""
    sq = packet.get("SqNum", 0)
    tdiff = packet.get("tDiff", 0)
    idle = packet.get("timeFromLastChange", 0)
    return sq < 5 and tdiff > 2000 and idle > 100

def rule_inverse_replay_state_lowdiff(packet: dict) -> bool:
    """Detect low state number together with an unusually large state-number jump."""
    st = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    return st < 174 and st_diff > 400

def rule_inverse_replay_state_tdiff(packet: dict) -> bool:
    """Detect low state number combined with a large timestamp difference."""
    st = packet.get("StNum", 0)
    tdiff = packet.get("tDiff", 0)
    return st < 174 and tdiff > 2000

def rule_inverse_replay_inactivity(packet: dict) -> bool:
    """Detect prolonged inactivity together with low sequence or state numbers."""
    idle = packet.get("timeFromLastChange", 0)
    sq = packet.get("SqNum", 0)
    st = packet.get("StNum", 0)
    return idle > 100 and (sq < 5 or st < 174)

def rule_masquerade_fake_normal_low_sqnum_high_stnum(packet: dict) -> bool:
    """Detect low SqNum combined with high StNum."""
    sq = packet.get("SqNum", 0)
    st = packet.get("StNum", 0)
    return sq < 4.9 and st > 669.4

def rule_masquerade_fake_normal_high_stnum_positive_stdiff(packet: dict) -> bool:
    """Detect high StNum together with a positive state-number difference."""
    st = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    return st > 669.4 and st_diff > 0

def rule_masquerade_fake_normal_positive_stdiff_short_time(packet: dict) -> bool:
    """Detect a large positive stDiff together with an unrealistically short interval."""
    st_diff = packet.get("stDiff", 0)
    time_last = packet.get("timeFromLastChange", 0)
    return st_diff > 266.75 and time_last < 0.557

def rule_poisoned_high_rate_seq_state(packet: dict) -> bool:
    """Detect low SqNum with abnormal sqDiff and high StNum."""
    sq = packet.get("SqNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    st = packet.get("StNum", 0)
    return (sq < 5) and (sqdiff < -45) and (st > 2000)

def rule_poisoned_high_rate_state_time(packet: dict) -> bool:
    """Detect excessively high StNum together with long timeFromLastChange."""
    st = packet.get("StNum", 0)
    tflc = packet.get("timeFromLastChange", 0)
    return (st > 2000) and (tflc > 5000)

def rule_poisoned_high_rate_breaker_delay(packet: dict) -> bool:
    """Detect forced breaker-closed status combined with large delay and timestamp gap."""
    cb = packet.get("cbStatus", 0)
    d = packet.get("delay", 0)
    tsdiff = packet.get("timestampDiff", 0)
    return (cb == 1) and (d > 0.0008) and (tsdiff > 2.0)

def rule_poisoned_high_rate_tdiff_combination(packet: dict) -> bool:
    """Detect very negative tDiff together with long timeFromLastChange and extreme sqDiff."""
    td = packet.get("tDiff", 0)
    tflc = packet.get("timeFromLastChange", 0)
    sqdiff = packet.get("sqDiff", 0)
    return (td < -500) and (tflc > 1000) and (sqdiff < -70)

def rule_random_replay_seq_state(packet: dict) -> bool:
    """Detect high sequence number together with unusually low state number."""
    sq = packet.get("SqNum", 0)
    st = packet.get("StNum", 0)
    return sq > 55 and st < 35

def rule_random_replay_timing(packet: dict) -> bool:
    """Detect excessive timestamp drift combined with a long idle interval."""
    ts_diff = packet.get("timestampDiff", 0)
    idle = packet.get("timeFromLastChange", 0)
    return ts_diff > 0.3765 and idle > 50.98

def rule_random_replay_state_jump(packet: dict) -> bool:
    """Detect a large backward state jump together with an outlier sequence jump."""
    st_diff = packet.get("stDiff", 0)
    sq_diff = packet.get("sqDiff", 0)
    return st_diff < -26046.85 and sq_diff > 31

def rule_random_replay_cb_flip(packet: dict) -> bool:
    """Detect a breaker

