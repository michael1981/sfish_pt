#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(25701);
  script_version ("$Revision: 1.11 $");

  script_name(english:"LDAP Crafted Search Request Server Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to discover information about the remote LDAP server." );
 script_set_attribute(attribute:"description", value:
"By sending a search request with a filter set to 'objectClass=*', it
is possible to extract information about the remote LDAP server." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_end_attributes();

  script_summary(english:"Retrives LDAP Base object information");
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

soc = open_sock_tcp(port);
if (!soc) exit(0);

ldap_init(socket:soc);

search = ldap_search_request(object:"", filter:"objectClass", attributes:"");
ret = ldap_request_sendrecv(data:search);

if (isnull(ret) || ret[0] != LDAP_SEARCH_RES_ENTRY)
  exit(0);

data = ldap_parse_search_entry(data:ret[1]);
if (isnull(data))
  exit(0);

report = NULL;

foreach item (data)
{
 report += string ("[+]-", item[0], ":\n");
 foreach value (item[1])
   report += string ("   |  ", value, "\n");

 if (item[0] == "vendorversion") item[0] = "vendorVersion";
 else if (item[0] == "vendorname") item[0] = "vendorName";

 if (item[0] == "vendorVersion" || item[0] == "vendorName")
 {
  val = item[1];
  val = val[0];
  if (val)
    set_kb_item(name:string("LDAP/",port,"/", item[0]), value:val);
 }
}

if (report)
{
 security_note(port:port, extra:report);
}
