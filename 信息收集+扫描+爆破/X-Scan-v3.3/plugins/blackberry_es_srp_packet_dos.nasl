#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(20983);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2005-2342");
  script_bugtraq_id(16100);
  script_xref(name:"OSVDB", value:"22155");

  script_name(english:"BlackBerry Enterprise Server Crafted SRP Packet Remote DoS");
  script_summary(english:"Checks version number of BlackBerry Enterprise Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows application is affected by a denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"A malicious user can cause a denial of service by sending malformed
SRP packets to the BlackBerry Router on port 3101. 

Note that successful exploitation of this issue by a remote attacker
is reportedly possible only through manipulation of DNS queries." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6aa8b9f8" );
 script_set_attribute(attribute:"solution", value:
"Install the appropriate service pack / hotfix as described in the
vendor advisory referenced above." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl");
  script_require_keys("BlackBerry_ES/Product", "BlackBerry_ES/Version");

  exit(0);
}


include("smb_func.inc");


prod = get_kb_item("BlackBerry_ES/Product");
ver = get_kb_item("BlackBerry_ES/Version");
if (prod && ver) {
  if (
    (
      "Domino" >< prod && 
      # fixed in 4.1.
      ver =~ "^([0-3]\.|4\.0\.)"
    ) ||
    (
      "Exchange" >< prod && 
      # fixed in 4.0.4.
      ver =~ "^([0-3]\..*|4\.0\.[0-3].*)"
    ) ||
    (
      "GroupWise" >< prod && 
      # unfixed currently.
      ver =~ "^([0-2]\..*|4\.0\.([0-2].*))"
    )
  ) {
    security_hole(kb_smb_transport());
  }
}
