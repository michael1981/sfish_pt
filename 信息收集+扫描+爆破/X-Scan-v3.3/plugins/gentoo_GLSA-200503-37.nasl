# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200503-37.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(17667);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200503-37");
 script_cve_id("CVE-2005-0788", "CVE-2005-0789");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200503-37 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200503-37
(LimeWire: Disclosure of sensitive information)


    Two input validation errors were found in the handling of Gnutella
    GET requests (CAN-2005-0788) and magnet requests (CAN-2005-0789).
  
Impact

    A remote attacker can craft a specific Gnutella GET request or use
    directory traversal on magnet requests to read arbitrary files on the
    system with the rights of the user running LimeWire.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All LimeWire users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-p2p/limewire-4.8.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0788');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0789');
script_set_attribute(attribute: 'see_also', value: 'http://secunia.com/advisories/14555/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200503-37.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200503-37] LimeWire: Disclosure of sensitive information');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'LimeWire: Disclosure of sensitive information');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-p2p/limewire", unaffected: make_list("ge 4.8.1"), vulnerable: make_list("lt 4.8.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
