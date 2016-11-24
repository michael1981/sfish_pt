#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38849);
  script_version("$Revision: 1.2 $");
  script_xref(name:"OSVDB", value:"23");

  script_name(english:"NSD version Directive Remote Version Disclosure");
  script_summary(english:"Checks the response of a VERSION.BIND request");

  script_set_attribute(
    attribute:"synopsis",
    value:"It is possible to obtain the version number of the remote DNS server."
  );
  script_set_attribute(
    attribute:"description",
    value:string(
      "The remote host is running Name Server Daemon (NSD), an open-source\n",
      "DNS server.  It is possible to extract the version number of the\n",
      "remote installation by sending a special DNS request for the text\n",
      "'version.bind' in the domain 'chaos'."
    )
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nlnetlabs.nl/projects/nsd/"
  );
  script_set_attribute(
    attribute:"solution",
    value:string(
      "It is possible to hide the version number of NSD by adding the\n",
      "following line to the server section of nsd.conf :\n",
      "\n",
      "  hide-version: yes"
    )
  );
  script_set_attribute(
    attribute:"risk_factor",
    value:"None"
  );
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item("bind/version");
if (isnull(version)) exit(0);

match = eregmatch(string:version, pattern:"^NSD ([0-9.]+)$", icase:TRUE);
if (isnull(match)) exit(0);

ver_num = match[1];
set_kb_item(name:"nsd/version", value:ver_num);
report = string(
  "\n",
  "The version of the remote NSD server is :\n\n",
  version
);
security_note(port:53, proto:"udp", extra:report);

