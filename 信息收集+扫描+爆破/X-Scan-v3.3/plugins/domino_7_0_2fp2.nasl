#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(27857);
  script_version("$Revision: 1.5 $");

  script_bugtraq_id(26298);

  script_name(english:"IBM Lotus Domino < 7.0.2 FP2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Lotus Domino");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of Lotus Domino on the remote host appears to be older
than 7.0.2 FP2.  According to IBM, such versions may be affected by
several security issues, depending on the specific version and its
configuration." );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg27009808" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Lotus Domino 7.0.2 FP2 or later." );
 script_set_attribute(attribute:"cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C" );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2007-2009 Tenable Network Security, Inc.");
  script_dependencies("domino_installed.nasl");
  script_require_keys("Domino/Version");

  exit(0);
}


# There's a problem if the version is < 7.0.2 FP2.
ver = get_kb_item("Domino/Version");
if (
  ver && 
  egrep(pattern:"^7\.0\.([01]($|[^0-9])|2($| FP1$))", string:ver)
) security_hole(0);
