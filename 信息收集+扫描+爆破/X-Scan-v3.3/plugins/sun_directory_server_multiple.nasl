#
# (C) Tenable Network Security
#



include("compat.inc");

if (description)
{
  script_id(25705);
  script_version("$Revision: 1.7 $");

  script_cve_id(
    "CVE-2006-4175", 
    "CVE-2007-2466", 
    "CVE-2007-3224", 
    "CVE-2007-3225"
  );
  script_bugtraq_id(23117, 23743, 24467, 24468);
  script_xref(name:"OSVDB", value:"33524");
  script_xref(name:"OSVDB", value:"35743");
  script_xref(name:"OSVDB", value:"37246");
  script_xref(name:"OSVDB", value:"37247");

  script_name(english:"Sun Java System Directory Server Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Sun Java Directory Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote LDAP server is prone to multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Sun Java System Directory Server, an
LDAP server from Sun Microsystems. 

The remote version of this service is affected by multiple
vulnerabilities.  Versions 6.0 and prior to 5.2 Patch 5 are vulnerable
to :

- list attributes information disclosure;
- Unauthorized Access (restricted to super users).

Versions prior to 5.2 Path 5 are vulnerable to :

- Denial of service due to the BER decoding handler;
- Memory corruption in the failed request handler." );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102876-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102875-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102895-1" );
 script_set_attribute(attribute:"see_also", value:"http://sunsolve.sun.com/search/document.do?assetkey=1-26-102853-1" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Jave System Directory Server 5.2 Patch 5 or 6.1" );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );

script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");

  script_dependencies("ldap_search.nasl");
  script_require_ports("Services/ldap", 389);

  exit(0);
}

port = get_kb_item("Services/ldap");
if (!port) port = 389;

ver = get_kb_item(string("LDAP/",port,"/vendorVersion"));
if (!ver)
  exit(0);


if ("Sun-Java(tm)-System-Directory/6.0" >< ver)
  security_hole(port);
else if (egrep(pattern:"Sun Java\(TM\) System Directory Server/", string:ver))
{
 major = ereg_replace(pattern:"^Sun Java\(TM\) System Directory Server/([0-9]+\.[0-9]+).*", string:ver, replace:"\1");
 major = split(major, sep:".", keep:FALSE);

 if (int(major[0]) < 5 ||
     (int(major[0]) == 5 && int(major[1]) < 2))
   security_hole(port);
 else if (int(major[0]) == 5 && int(major[1]) == 2)
 {
  if (egrep(pattern:".*_Patch_[0-9]+$", string:ver))
  {
   patch = ereg_replace(pattern:".*_Patch_([0-9])+$", string:ver, replace:"\1");
   if (int(patch) < 5)
     security_hole(port);
  }
  else security_hole(port);
 }
}

