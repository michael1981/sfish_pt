#
# This script was written by John Lampe (j_lampe@bellsouth.net)
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, family change (9/1/09)


include("compat.inc");

if(description)
{
  script_id(10722);
  script_version ("$Revision: 1.17 $");

  script_name(english:"LDAP NULL BASE Search Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server may disclose sensitive information." );
 script_set_attribute(attribute:"description", value:
"The remote LDAP server supports search requests with a null, or empty,
base object.  This allows information to be retrieved without any
prior knowledge of the directory structure.  Coupled with a NULL BIND,
an anonymous user may be able to query your LDAP server using a tool
such as 'LdapMiner'. 

Note that there are valid reasons to allow queries with a null base. 
For example, it is required in version 3 of the LDAP protocol to
provide access to the root DSA-Specific Entry (DSE), with information
about the supported naming context, authentication types, and the
like.  It also means that legitimate users can find information in the
directory without any a priori knowledge of its structure.  As such,
this finding may be a false-positive." );
 script_set_attribute(attribute:"solution", value:
"If the remote LDAP server supports a version of the LDAP protocol
before v3, consider whether to disable NULL BASE queries on your LDAP
server." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N" );

script_end_attributes();

  script_summary(english:"Check for LDAP null base");
  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");
  script_copyright(english:"(C) 2009 John Lampe <j_lampe@bellsouth.net>");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}



#
# The script code starts here


string1 = raw_string (0x30,0x0C,0x02,0x01,0x01,0x60,0x07,0x02,0x01,0x02,0x04,0x00,0x80,0x80);
string2 = raw_string (0x30, 0x25, 0x02, 0x01, 0x02, 0x63, 0x20, 0x04, 0x00, 0x0A, 0x01, 0x00, 0x0A, 0x01, 0x00, 0x02,
                      0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0B, 0x6F, 0x62, 0x6A, 0x65, 0x63, 0x74,
                      0x63, 0x6C, 0x61, 0x73, 0x73, 0x30, 0x00);
mystring = string(string1, string2);
positiveid = "supportedVersion";

port = get_kb_item("Services/ldap");
if (!port) port = 389;

if (get_port_state(port)) {
    soc = open_sock_tcp(port);
    if (!soc) {
        exit(0);
    }

    send(socket:soc, data:mystring);
    rez = recv(socket:soc, length:4096);
    l = strlen(rez);
    if (l >= 7)
    {
      error_code = substr(rez, l - 7, l - 5);
      if (hexstr(error_code) == "0a0100") security_warning(port);
    }
}



