# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200504-05.xml
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
 script_id(17992);
 script_version("$Revision: 1.7 $");
 script_xref(name: "GLSA", value: "200504-05");
 script_cve_id("CVE-2005-0967", "CVE-2005-0966", "CVE-2005-0965");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200504-05 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200504-05
(Gaim: Denial of Service issues)


    Multiple vulnerabilities have been addressed in the latest release of
    Gaim:
    A buffer overread in the gaim_markup_strip_html() function,
    which is used when logging conversations (CAN-2005-0965).
    Markup tags are improperly escaped using Gaim\'s IRC plugin
    (CAN-2005-0966).
    Sending a specially crafted file transfer request to a Gaim Jabber
    user can trigger a crash (CAN-2005-0967).
  
Impact

    An attacker could possibly cause a Denial of Service by exploiting any
    of these vulnerabilities.
  
Workaround

    There is no known workaround at this time.
  
');
script_set_attribute(attribute:'solution', value: '
    All Gaim users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-im/gaim-1.2.1"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0967');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0966');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CAN-2005-0965');
script_set_attribute(attribute: 'see_also', value: 'http://gaim.sourceforge.net/security/');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200504-05.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200504-05] Gaim: Denial of Service issues');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Gaim: Denial of Service issues');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-im/gaim", unaffected: make_list("ge 1.2.1"), vulnerable: make_list("lt 1.2.1")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
