import iptc



def add_new_rule_drop(ip_address,tcp):

    """
    get the bad ip 
    add rule in filter table to get rid of said IP
    make sure wed can find way to make ip_address a string from where ver we pull it or convert it to a string
    """
    table = iptc.Table(iptc.Table.FILTER)
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")


# Access the filter table
    table = iptc.Table(iptc.Table.FILTER)

    # Access the INPUT chain
    #chain = iptc.Chain(table, "INPUT")
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")

# Create a new rule
    rule = iptc.Rule()

# Set the source IP address
    rule.src = ip_address

# Set the target to DROP
    rule.target = iptc.Target(rule, "DROP")

# Append the rule to the INPUT chain
    chain.append_rule(rule)

    print("Rule added successfully!")


def add_new_rule_match(ip_address,protocol):


#    Access the filter table
    table = iptc.Table(iptc.Table.FILTER)

# Access the INPUT chain
    chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")

# Create a new rule
    rule = iptc.Rule()

# Set the protocol (optional, can be omitted for state-based rules)
    rule.protocol = protocol

# Create a match for the connection state
    match = rule.create_match("state")
    match.state = "ESTABLISHED,RELATED"

# Set the target to ACCEPT
    rule.target = iptc.Target(rule, "ACCEPT")

# Append the rule to the INPUT chain
    chain.append_rule(rule)

