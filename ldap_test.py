from ldap3 import Server, Connection, SUBTREE, ALL_ATTRIBUTES, SIMPLE, NTLM, AUTO_BIND_TLS_BEFORE_BIND, Tls
import ssl
import socket

# Get your computer's domain
current_domain = socket.getfqdn().split('.', 1)[1] if '.' in socket.getfqdn() else None
print(f"Detected domain: {current_domain}")

# Connection parameters - replace these with your specifics
domain_name = current_domain  # Use detected domain or replace with your actual domain
username = "user1"
password = "0password1"
target_username = "user1"

# Try multiple username formats
username_formats = [
    f"{domain_name}\\{username}",  # DOMAIN\username
    f"{username}@{domain_name}",    # username@domain.com
    username,                       # Just username
    f"CN={username},CN=Users,DC={domain_name.replace('.', ',DC=')}"  # Distinguished Name
]

# Try to find domain controllers automatically
domain_controllers = []
try:
    import dns.resolver
    answers = dns.resolver.resolve(f'_ldap._tcp.{domain_name}', 'SRV')
    for answer in answers:
        domain_controllers.append(str(answer.target).rstrip('.'))
    print(f"Found domain controllers via DNS: {domain_controllers}")
except:
    # Fallback to common naming patterns
    domain_parts = domain_name.split('.')
    domain_controllers = [
        f"dc.{domain_name}",
        f"ad.{domain_name}",
        domain_name,
        f"dc1.{domain_name}",
        f"ads.{domain_name}"
    ]
    print(f"Using default domain controller patterns: {domain_controllers}")

# Create TLS configuration for secure connection
tls_config = Tls(validate=ssl.CERT_NONE)  # Don't validate cert in test environment

# Try different combinations until one works
connected = False

for dc in domain_controllers:
    for username_format in username_formats:
        for auth_method in ['NTLM', 'SIMPLE']:
            try:
                print(f"Trying to connect to {dc} with {username_format} using {auth_method}...")
                
                # Create server - try both LDAP and LDAPS
                for protocol in ['ldap://', 'ldaps://']:
                    try:
                        if protocol == 'ldaps://':
                            server = Server(f"{protocol}{dc}", use_ssl=True, tls=tls_config)
                        else:
                            server = Server(f"{protocol}{dc}")
                            
                        # Create connection
                        if auth_method == 'NTLM':
                            conn = Connection(
                                server, 
                                user=username_format,
                                password=password,
                                authentication=NTLM,
                                auto_bind=True
                            )
                        else:
                            conn = Connection(
                                server, 
                                user=username_format,
                                password=password,
                                authentication=SIMPLE,
                                auto_bind=True
                            )
                        
                        print(f"SUCCESS! Connected to {protocol}{dc} with {username_format} using {auth_method}")
                        connected = True
                        break
                    except Exception as e:
                        print(f"  Failed with {protocol}{dc}: {str(e)}")
                        continue
                
                if connected:
                    break
            except Exception as e:
                print(f"  Failed: {str(e)}")
                continue
        
        if connected:
            break
    
    if connected:
        break

if connected:
    # Successfully connected, now search for the user
    print("\nSearching for user...")
    
    # Build search base from domain components
    search_base = ','.join([f"DC={dc}" for dc in domain_name.split('.')])
    search_filter = f"(&(objectClass=user)(sAMAccountName={target_username}))"
    
    # Perform the search
    conn.search(
        search_base=search_base,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=ALL_ATTRIBUTES
    )
    
    # Display the results
    if len(conn.entries) > 0:
        user = conn.entries[0]
        print(f"\nUser information for: {target_username}")
        print("-" * 50)
        
        # Print all attributes
        for attr_name in user.entry_attributes:
            print(f"{attr_name}: {user[attr_name]}")
    else:
        print(f"User {target_username} not found")
else:
    print("\nFailed to connect to Active Directory with the provided credentials.")
    print("Possible solutions:")
    print("1. Verify your username and password")
    print("2. Check if your account is locked or expired")
    print("3. Ensure you have network connectivity to the domain controller")
    print("4. Verify that your account has permission to query the directory")