#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10723);
  script_version ("$Revision: 1.26 $");
  script_xref(name:"OSVDB", value:"9723");

  script_name(english:"LDAP Server NULL Bind Connection Information Disclosure");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote LDAP server allows anonymous access."
  );
  script_set_attribute(
    attribute:"description", 
    value:string(
      "The LDAP server on the remote host is currently configured such that a\n",
      "user can connect to it without authentication - via a 'NULL BIND' -\n",
      "and query it for information.  Although the queries that are allowed\n",
      "are likely to be fairly restricted, this may result in disclosure of\n",
      "information that an attacker could find useful. \n",
      "\n",
      "Note that version 3 of the LDAP protocol requires that a server allow\n",
      "anonymous access -- a 'NULL BIND' -- to the root DSA-Specific Entry\n",
      "(DSE) even though it may still require authentication to perform other\n",
      "queries.  As such, this finding may be a false-positive."
    )
  );
  script_set_attribute(
    attribute:"solution", 
    value:string(
      "Unless the remote LDAP server supports LDAP v3, configure it to\n",
      "disallow NULL BINDs."
    )
  );
  script_set_attribute(
    attribute:"cvss_vector", 
    value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N"
  );
  script_end_attributes();

  script_summary(english:"Check for LDAP null bind");

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}


include("kerberos_func.inc");
include("ldap_func.inc");

port = get_kb_item("Services/ldap");
if (!port) port = 389;
if (!get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(0);

ldap_init(socket:soc);

# nb: LDAP v3 requires anonymous access to the RootDSE so 
#     using that would ensure the bind works.
data = 
	der_encode_int(i:2)                 +  # LDAP version
	der_encode_octet_string(string:"")  +  # name
	der_encode(tag:LDAP_AUTHENTICATION_TAG, data:"");

bind = ldap_request(code:LDAP_BIND_REQUEST, data:data);
ret = ldap_request_sendrecv(data:bind);

if (isnull(ret) || ret[0] != LDAP_BIND_RESPONSE)
  exit(0);

data = ldap_parse_bind_response(data:ret[1]);
if (isnull(data))
  exit(0);

if (data[0] == 0)
  security_warning(port);
