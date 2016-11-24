#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22311);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2006-4095", "CVE-2006-4096");
  script_bugtraq_id(19859);
  script_xref(name:"OSVDB", value:"28557");
  script_xref(name:"OSVDB", value:"28558");

  script_name(english:"ISC BIND 9 Multiple Remote DoS");
  script_summary(english:"Checks version of BIND");

 script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by multiple denial of service
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of BIND installed on the remote host suggests that it
suffers from multiple denial of service vulnerabilities, which may be
triggered by either by sending a large volume of recursive queries or
queries for SIG records where there are multiple SIG(covered) RRsets. 

Note that Nessus obtained the version by sending a special DNS request
for the text 'version.bind' in the domain 'chaos', the value of which
can be and sometimes is tweaked by DNS administrators." );
 script_set_attribute(attribute:"see_also", value:"http://www.cpni.gov.uk/Docs/re-20060905-00590.pdf" );
 script_set_attribute(attribute:"see_also", value:"https://www.isc.org/node/397" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.4.0b2 / 9.3.3rc2 / 9.3.2-P1 / 9.2.7rc2 / 9.2.6-P1 or
later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P" );
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english: "DNS");

  script_copyright(english:"This script is Copyright (C) 2006-2009 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version");

  exit(0);
}


include("global_settings.inc");


# Banner checks of BIND are prone to false-positives so we only
# run the check if reporting is paranoid.
if (report_paranoia <= 1) exit(0);


ver = get_kb_item("bind/version");
if (!ver) exit(0);

if (ver =~ "^9\.(2\.([0-5][^0-9]?|6(b|rc|$)|7(b|rc1))|3\.([01][^0-9]?|2(b|rc|$)|3(b|rc1))|4\.0b1)")
  security_warning(53);
