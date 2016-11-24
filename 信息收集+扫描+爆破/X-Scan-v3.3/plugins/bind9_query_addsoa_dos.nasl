#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25121);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2007-2241");
  script_bugtraq_id(23738);
  script_xref(name:"OSVDB", value:"34748");

  script_name(english:"ISC BIND < 9.4.1 / 9.5.0a4 query.c query_addsoa Function Recursive Query DoS");
  script_summary(english:"Checks version of BIND");

 script_set_attribute(attribute:"synopsis", value:
"The remote name server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The version of BIND installed on the remote host reportedly is
affected by a denial of service vulnerability that may be triggered
when handling certain sequences of recursive queries." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bind-users&m=117781099030155&w=2" );
 script_set_attribute(attribute:"see_also", value:"https://www.isc.org/node/394" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bind-announce&m=117798912418849&w=2" );
 script_set_attribute(attribute:"solution", value:
"Either disable recursion or upgrade to BIND 9.4.1 / 9.5.0a4 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english: "DNS");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version");

  exit(0);
}


include("global_settings.inc");


# Banner checks of BIND are prone to false-positives so we only
# run the check if reporting is paranoid.
if (report_paranoia < 2) exit(0);


ver = get_kb_item("bind/version");
if (ver && ver =~ "^9\.(4\.0[^0-9]?|5\.0a[1-3])")
  security_hole(53);
