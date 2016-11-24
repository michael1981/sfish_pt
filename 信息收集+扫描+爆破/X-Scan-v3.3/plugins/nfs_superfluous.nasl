#
# (C) Tenable Network Security, Inc.
#

#
# Get the export list of the remote host and
# warns the user if a NFS share is exported to the
# world.

include( 'compat.inc' );

if(description)
{
  script_id(42255);
  script_version ("$Revision: 1.1 $");

  script_cve_id("CVE-1999-0548");

  script_name(english: "NFS Server Superfluous");
  script_summary(english: "Checks if the NFS server isn't exporting anything");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote host is running an unnecessary service."
  );

  script_set_attribute(
    attribute:'description',
    value:string(
      "The remote NFS server is not exporting any shares.  Running an\n",
      "unused service unnecessarily increases the attack surface of the\n",
      "remote host."
    )
  );

  script_set_attribute(
    attribute:'solution',
    value:"Disable this service."
  );

  script_set_attribute(
    attribute:'risk_factor',
    value:'None'
  );

  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/10/26"
  );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
  script_family(english: "RPC");
  script_dependencie("showmount.nasl");
  script_require_keys("nfs/proto", "nfs/noshares");
  exit(0);
}

include("misc_func.inc");

proto = get_kb_item("nfs/proto");

if (get_kb_item("nfs/noshares"))
  security_note(port:2049, proto:proto);
