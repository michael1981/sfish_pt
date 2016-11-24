# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200703-03.xml
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
 script_id(24751);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200703-03");
 script_cve_id("CVE-2007-0897", "CVE-2007-0898");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200703-03 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200703-03
(ClamAV: Denial of Service)


    An anonymous researcher discovered a file descriptor leak error in the
    processing of CAB archives and a lack of validation of the "id"
    parameter string used to create local files when parsing MIME headers.
  
Impact

    A remote attacker can send several crafted CAB archives with a
    zero-length record header that will fill the available file descriptors
    until no other is available, which will prevent ClamAV from scanning
    most archives. An attacker can also send an email with specially
    crafted MIME headers to overwrite local files with the permissions of
    the user running ClamAV, such as the virus database file, which could
    prevent ClamAV from detecting any virus.
  
Workaround

    The first vulnerability can be prevented by refusing any file of type
    CAB, but there is no known workaround for the second issue.
  
');
script_set_attribute(attribute:'solution', value: '
    All ClamAV users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-antivirus/clamav-0.90"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0897');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-0898');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-03.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200703-03] ClamAV: Denial of Service');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'ClamAV: Denial of Service');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-antivirus/clamav", unaffected: make_list("ge 0.90"), vulnerable: make_list("lt 0.90")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
