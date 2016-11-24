#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(42256);
  script_version ("$Revision: 1.1 $");

  script_xref(name:"OSVDB", value:"339");

  script_name(english: "NFS Shares World Readable");
  script_summary(english: "Checks if host-based ACLs are being used");

  script_set_attribute(
    attribute:'synopsis',
    value:"The remote NFS server exports world readable shares."
  );

  script_set_attribute(
    attribute:'description',
    value:string(
      "The remote NFS server is exporting one or more shares without\n",
      "restricting access (based on hostname, IP, or IP range)."
    )
  );

  script_set_attribute(
    attribute:'solution',
    value:"Place the appropriate restrictions on all NFS shares."
  );

  script_set_attribute(
    attribute:'see_also',
    value:"http://www.tldp.org/HOWTO/NFS-HOWTO/security.html"
  );

  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N'
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
  script_require_keys("nfs/proto", "nfs/share_acl");
  exit(0);
}

include("misc_func.inc");

proto = get_kb_item("nfs/proto");
list = get_kb_list("nfs/share_acl");
if (isnull(list)) exit(0, "The NFS server doesn't have any shares.");
shares = make_list(list);

report = string("\nThe following shares have no access restrictions :\n\n");
vuln = FALSE;

foreach share (shares)
{
  share_info = split(share, sep:" ", keep:FALSE);
  acl = share_info[1];

  if (acl && acl == "*")
  {
    report += string("  ", share, "\n");
    vuln = TRUE;
  }
}

if (vuln)
  security_warning(port:2049, proto:proto, extra:report);
else exit(0, "The NFS server doesn't have any world-readable shares.");
