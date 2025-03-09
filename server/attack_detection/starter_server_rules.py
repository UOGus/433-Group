import iptc

""" idea for this is the server's basic rules at the start(currently incomplete),
 may also include baisc attack detction 
later"""

# rate limit rule, equivlent to: iptables -A INPUT -p tcp -m limit --limit 10/sec --limit-burst 20 -j DROP command line

rate_limit_rule=iptc.Rule()

rate_limit_rule.protocol="tcp"

rate_limit_rule.target=iptc.Target(rule, "DROP") 

# Match for rate limiting
match = rate_limit_rule.create_match("limit")
match.limit = "10/sec"  # Limit to 10 packets per second, can be any value
match.limit_burst = "20"  # Allow a burst of 20 packets, can be any int we want

# Add the rule to the INPUT chain
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rate_limit_rule)



#ICMP drop rule: drops all packets

icmp_rule=iptc.Rule()

icmp_rule.protocol= "icmp" # Specify ICMP protocol

icmp_rule.target=iptc.Target(icmp_rule,"DROP")

# Add the rule to the INPUT chain
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rate_limit_rule)
