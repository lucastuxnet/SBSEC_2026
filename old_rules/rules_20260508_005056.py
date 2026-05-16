# Regras de detecção geradas pelo LLM (limpas)
# Origem: rules_raw.py
# Data: 08/05/2026 00:17:45
# Para uso no pipeline de detecção GOOSE IEC 61850

def rule_sqnum_low(packet: dict) -> bool:
    sq = packet.get("SqNum", 0)
    sq_diff = packet.get("sqDiff", 0)
    return sq < 12 and sq_diff > -2

def rule_sqnum_stnum_combo(packet: dict) -> bool:
    sq = packet.get("SqNum", 0)
    st = packet.get("StNum", 0)
    return sq < 15 and st < 250

def rule_sqnum_timestamp(packet: dict) -> bool:
    sq_diff = packet.get("sqDiff", 0)
    t_diff = packet.get("tDiff", 0)
    return sq_diff > -2 and t_diff > 0.5

def rule_sqnum_misc(packet: dict) -> bool:
    cb_diff = packet.get("cbStatusDiff", 0)
    goose_len_diff = packet.get("gooseLengthDiff", 0)
    return cb_diff == 0 and goose_len_diff == 0

def rule_excessive_state_number_jump(packet: dict) -> bool:
    """Detects a massive State-Number jump combined with a large state-time difference."""
    st_num = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    return st_num > 10000 and st_diff > 20000

def rule_abnormal_stnum_increment_rate(packet: dict) -> bool:
    """Detects an unusually high State-Number increment rate together with a long timestamp gap."""
    st_diff = packet.get("stDiff", 0)
    timestamp_diff = packet.get("timestampDiff", 0)
    return st_diff > 15000 and timestamp_diff > 5000

def rule_elevated_sequence_number_growth(packet: dict) -> bool:
    """Detects rapid Sequence-Number growth coupled with a significant sequence diff."""
    sq_num = packet.get("SqNum", 0)
    sq_diff = packet.get("sqDiff", 0)
    return sq_num > 30 and sq_diff > 10

def rule_inconsistent_timestamp_and_sequence(packet: dict) -> bool:
    """Detects decoupling between state-time difference and sequence-number difference."""
    st_diff = packet.get("stDiff", 0)
    sq_diff = packet.get("sqDiff", 0)
    return abs(st_diff - sq_diff * 1000) > 5000

def rule_sqnum_jump_large(packet: dict) -> bool:
    """Detect large jump in SqNum with high sqDiff."""
    return packet.get("sqDiff", 0) > 30 and packet.get("SqNum", 0) > 50

def rule_sqnum_unexpected_timing(packet: dict) -> bool:
    """Detect large sqDiff together with abnormal negative stDiff."""
    return packet.get("sqDiff", 0) > 20 and packet.get("stDiff", 0) < -10000

def rule_sqnum_no_apdu_change(packet: dict) -> bool:
    """Detect large sqDiff while APDU size does not change."""
    return packet.get("sqDiff", 0) > 25 and packet.get("apduSizeDiff", 0) == 0

def rule_sqnum_cbstatus_variation(packet: dict) -> bool:
    """Detect large sqDiff accompanied by significant cbStatus variation."""
    return packet.get("sqDiff", 0) > 20 and abs(packet.get("cbStatusDiff", 0)) > 0.5

def rule_low_stnum_sqnum(packet: dict) -> bool:
    stnum = packet.get("StNum", 0)
    sqnum = packet.get("SqNum", 0)
    return stnum < 200 and sqnum < 10

def rule_positive_stdiff_negative_sqdiff(packet: dict) -> bool:
    st_diff = packet.get("stDiff", 0)
    sq_diff = packet.get("sqDiff", 0)
    return st_diff > 0 and sq_diff < 0

def rule_small_cbstatus_change(packet: dict) -> bool:
    cb_status = packet.get("cbStatus", 0)
    cb_status_diff = packet.get("cbStatusDiff", 0)
    return cb_status > 0.2 and cb_status_diff < 0.3

def rule_zero_size_diff_with_anomalies(packet: dict) -> bool:
    goose_len_diff = packet.get("gooseLengthDiff", 0)
    apdu_size_diff = packet.get("apduSizeDiff", 0)
    st_diff = packet.get("stDiff", 0)
    sq_diff = packet.get("sqDiff", 0)
    return goose_len_diff == 0 and apdu_size_diff == 0 and (st_diff > 0 or sq_diff < 0)

def rule_red_flag_1_a(packet: dict) -> bool:
    """Retorna True se o pacote apresentar queda abrupta de StNum."""
    stnum = packet.get("StNum", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum < 200) and (stdiff > -500)

def rule_red_flag_1_b(packet: dict) -> bool:
    """Retorna True se StNum estiver baixo e SqNum não apresentar incremento esperado."""
    stnum = packet.get("StNum", 0)
    sqnum = packet.get("SqNum", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum < 250) and (sqnum < 20) and (stdiff > -1000)

def rule_red_flag_1_c(packet: dict) -> bool:
    """Retorna True se houver mudança de status do disjuntor sem incremento adequado de StNum."""
    stnum = packet.get("StNum", 0)
    cbstatusdiff = packet.get("cbStatusDiff", 0)
    stdiff = packet.get("stDiff", 0)
    return (cbstatusdiff > 0.5) and (stnum < 300) and (stdiff > -800)

def rule_red_flag_1_d(packet: dict) -> bool:
    """Retorna True se StNum baixo coincidir com ausência de variação de tamanho do payload."""
    stnum = packet.get("StNum", 0)
    gooseLengthDiff = packet.get("gooseLengthDiff", 0)
    apduSizeDiff = packet.get("apduSizeDiff", 0)
    stdiff = packet.get("stDiff", 0)
    return (stnum < 250) and (gooseLengthDiff == 0) and (apduSizeDiff == 0) and (stdiff > -600)

def rule_sqnum_low_static1(packet: dict) -> bool:
    sqnum = packet.get("SqNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    return sqnum < 5 and sqdiff < 1

def rule_sqnum_low_static2(packet: dict) -> bool:
    sqnum = packet.get("SqNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    stnum = packet.get("StNum", 0)
    return sqnum < 10 and sqdiff <= 0.5 and stnum > 300

def rule_sqnum_low_static3(packet: dict) -> bool:
    sqnum = packet.get("SqNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    stdiff = packet.get("stDiff", 0)
    return sqnum < 8 and sqdiff < 1 and stdiff > 0

def rule_sqnum_low_static4(packet: dict) -> bool:
    sqnum = packet.get("SqNum", 0)
    sqdiff = packet.get("sqDiff", 0)
    cbstatus = packet.get("cbStatus", 0)
    return sqnum < 12 and (sqdiff / (sqnum + 1)) < 0.1 and cbstatus == 0

def rule_sudden_massive_stnum_jump_1(packet):
    return packet.get("StNum", 0) > 3000 and packet.get("stDiff", 0) > 0

def rule_sudden_massive_stnum_jump_2(packet):
    return (packet.get("StNum", 0) - packet.get("SqNum", 0)) > 2500 and packet.get("stDiff", 0) > 10

def rule_sudden_massive_stnum_jump_3(packet):
    return packet.get("StNum", 0) > 1000 and packet.get("cbStatusDiff", 0) > 0.1

def rule_sudden_massive_stnum_jump_4(packet):
    return packet.get("StNum", 0) > 2000 and packet.get("gooseLengthDiff", 0) == 0 and packet.get("apduSizeDiff", 0) == 0

def rule_stnum_regression_a(packet: dict) -> bool:
    st_num = packet.get("StNum", 0)
    st_diff = packet.get("stDiff", 0)
    return st_diff < -5000 and st_num < 250

def rule_stnum_regression_b(packet: dict) -> bool:
    st_diff = packet.get("stDiff", 0)
    goose_len_diff = packet.get("gooseLengthDiff", 0)
    return st_diff < -3000 and goose_len_diff == 0

def rule_stnum_regression_c(packet: dict) -> bool:
    st_diff = packet.get("stDiff", 0)
    sq_diff = packet.get("sqDiff", 0)
    return st_diff < -2000 and sq_diff < -2

def rule_stnum_regression_d(packet: dict) -> bool:
    st_num = packet.get("StNum", 0)
    cb_status_diff = packet.get("cbStatusDiff", 0)
    return st_num < 300 and cb_status_diff > 0.5

