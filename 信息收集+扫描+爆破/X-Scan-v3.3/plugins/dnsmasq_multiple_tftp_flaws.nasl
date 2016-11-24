#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(40875);
  script_version("$Revision: 1.1 $");

  script_cve_id( "CVE-2009-2957", "CVE-2009-2958" );
  script_bugtraq_id( 36120, 36121 );
  script_xref(name:"OSVDB", value:"57592");
  script_xref(name:"OSVDB", value:"57593");

  script_name(english:"dnsmasq < 2.50 Multiple Remote TFTP Vulnerabilities");
  script_summary(english: "Checks the version of dnsmasq");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote TFTP service is affected by multiple vulnerabilities.'
  );

  script_set_attribute(
    attribute:'description',
    value:'The remote host is running dnsmasq, a DNS and TFTP server. 

The version of dnsmasq installed on the remote host reports itself as
lower than 2.50.  Such versions include a TFTP server that is
reportedly affected by a number of issues:

  - A remote heap-overflow vulnerability exists because the
    software fails to properly bounds-check user-supplied 
    input before copying it into an insufficiently-sized 
    memory buffer. (CVE-2009-2957)

  - A malformed TFTP packet can crash dnsmasq with a NULL
    pointer dereference. (CVE-2009-2958)'
  );

  script_set_attribute(
    attribute:'see_also',
    value:'http://www.coresecurity.com/content/dnsmasq-vulnerabilities'
  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://archives.neohapsis.com/archives/fulldisclosure/2009-08/0451.html'
  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://www.thekelleys.org.uk/dnsmasq/CHANGELOG'
  );
  script_set_attribute(
    attribute:'see_also',
    value:'http://lists.thekelleys.org.uk/pipermail/dnsmasq-discuss/2009q3/003253.html'
  );
  script_set_attribute(
    attribute:'solution',
    value:'Upgrade to dnsmasq 2.50 or later.'
  );
  script_set_attribute(
    attribute:'cvss_vector',
    value:'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C'
  );

  script_set_attribute( attribute:'vuln_publication_date', value:'2009/08/31' );
  script_set_attribute( attribute:'patch_publication_date', value:'2009/08/31' );
  script_set_attribute( attribute:'plugin_publication_date', value:'2009/09/04' );

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2009 Tenable Network Security, Inc.");
  script_family(english: "DNS");

  script_dependencies("bind_version.nasl", "tftpd_detect.nasl");
  script_require_keys("bind/version");
  exit(0);
}

include("global_settings.inc");

if (report_paranoia < 2)
  exit( 1, "Banner checks of open source software are prone to false positives and aren't performed unless Report paranoia is set to 'Paranoid'.");

port = get_kb_item( "Services/udp/tftp" );
# dnsmasq always replies to BIND.VERSION
if ( isnull( port ) )
  exit( 0, 'TFTP service has not been detected.' );

vers = get_kb_item("bind/version");
if ( vers && ereg(pattern:"dnsmasq-([01]\.|2\.([0-9]|[1-4][0-9])$)", string:vers) )
	security_hole(port:port, proto:"udp");
