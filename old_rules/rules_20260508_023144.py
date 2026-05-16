# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 08/05/2026 01:56:19
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_grayhole_seq_tdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole (baixo SqNum e alto tDiff)."""
    sq_num = packet.get("SqNum", 0)
    t_diff = packet.get("tDiff", 0)
    return (sq_num < 0.5) and (t_diff > 1500)

def rule_grayhole_seq_stnum(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de grayhole (baixo SqNum e baixo StNum)."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num < 0.5) and (st_num < 10)


# === high_StNum ===

def rule_high_StNum_core(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum (core)."""
    StNum = packet.get("StNum", 0)
    stDiff = packet.get("stDiff", 0)
    return (StNum > 1000) and (stDiff > 1000)

def rule_high_StNum_aux(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de high_StNum (aux)."""
    SqNum = packet.get("SqNum", 0)
    tDiff = packet.get("tDiff", 0)
    return (SqNum > 70) and (tDiff > 2000)


# === injection ===

def rule_injection_seq_time(packet: dict) -> bool:
    """Retorna True se o pacote apresentar anomalias de sequência e timestamp."""
    sq_diff = packet.get("sqDiff", 0)
    t_diff = packet.get("tDiff", 0)
    return (sq_diff > 31) and (t_diff < -120.4257)

def rule_injection_status_st(packet: dict) -> bool:
    """Retorna True se o pacote apresentar status de breaker inválido e mudança de estado anômala."""
    cb_status = packet.get("cbStatus", 0)
    st_diff = packet.get("stDiff", 0)
    time_last = packet.get("timeFromLastChange", 0)
    return (cb_status > 1) and (st_diff < -61895.9) and (time_last < 0)


# === inverse_replay ===

def rule_inverse_replay_stdiff_tdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay baseado em stDiff e tDiff."""
    st_diff = packet.get("stDiff", 0)
    t_diff = packet.get("tDiff", 0)
    return (st_diff > 400) and (t_diff > 2000)

def rule_inverse_replay_stnum_idle(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de inverse_replay baseado em StNum e timeFromLastChange."""
    st_num = packet.get("StNum", 0)
    idle_time = packet.get("timeFromLastChange", 0)
    return (st_num < 35) and (idle_time > 51)


# === masquerade_fake_fault ===

def rule_masquerade_fake_fault_time(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_fault (tempo)."""
    tDiff = packet.get("tDiff", 0)
    timestampDiff = packet.get("timestampDiff", 0)
    return (tDiff > 1500) and (timestampDiff > 0.4)

def rule_masquerade_fake_fault_misc(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_fault (outros)."""
    tDiff = packet.get("tDiff", 0)
    stDiff = packet.get("stDiff", 0)
    return (tDiff > 1500) and (stDiff > 500)


# === masquerade_fake_normal ===

def rule_masquerade_fake_normal_stnum_stdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum > 1000) and (stdiff > 400)

def rule_masquerade_fake_normal_stnum_tdiff(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de masquerade_fake_normal."""
    stnum = packet.get("StNum", 0)
    tdiff = packet.get("tDiff", 0)
    return (stnum > 1000) and (tdiff > 1500)


# === poisoned_high_rate ===

def rule_poisoned_high_rate_stnum_delay(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de poisoned_high_rate (StNum alto e delay elevado)."""
    stnum = packet.get("StNum", 0)
    delay = packet.get("delay", 0)
    return (stnum > 679) and (delay > 0.0005)

def rule_poisoned_high_rate_sqdiff_timestamp(packet: dict) -> bool:
    """Retorna True se o pacote for suspeito de poisoned_high_rate (sqDiff muito negativo e grande gap de timestamp)."""
    sqdiff = packet.get("sqDiff", 0)
    tsdiff = packet.get("timestampDiff", 0)
    return (sqdiff <= -64) and (tsdiff > 0.3765)


# === random_replay ===

def rule_random_replay_seq_state(packet: dict) -> bool:
    """Detect random replay by abnormal sequence and state numbers."""
    sq_num = packet.get("SqNum", 0)
    st_num = packet.get("StNum", 0)
    return (sq_num > 55) and (st_num < 35)

def rule_random_replay_timing(packet: dict) -> bool:
    """Detect random replay by extreme differences in sequence and state timing."""
    sq_diff = packet.get("sqDiff", 0)
    st_diff = packet.get("stDiff", 0)
    return (sq_diff > 31) and (st_diff < -61895.9)

