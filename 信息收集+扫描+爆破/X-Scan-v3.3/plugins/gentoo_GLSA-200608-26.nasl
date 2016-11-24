# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200608-26.xml
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
 script_id(22288);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200608-26");
 script_cve_id("CVE-2006-4330", "CVE-2006-4331", "CVE-2006-4332", "CVE-2006-4333");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200608-26 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200608-26
(Wireshark: Multiple vulnerabilities)


    The following vulnerabilities have been discovered in Wireshark.
    Firstly, if the IPsec ESP parser is used it is susceptible to
    off-by-one errors, this parser is disabled by default; secondly, the
    SCSI dissector is vulnerable to an unspecified crash; and finally, the
    Q.2931 dissector of the SSCOP payload may use all the available memory
    if a port range is configured. By default, no port ranges are
    configured.
  
Impact

    An attacker might be able to exploit these vulnerabilities, resulting
    in a crash or the execution of arbitrary code with the permissions of
    the user running Wireshark, possibly the root user.
  
Workaround

    Disable the SCSI and Q.2931 dissectors with the "Analyse" and "Enabled
    protocols" menus. Make sure the ESP decryption is disabled, with the
    "Edit -> Preferences -> Protocols -> ESP" menu.
  
');
script_set_attribute(attribute:'solution', value: '
    All Wireshark users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-analyzer/wireshark-0.99.3"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4330');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4331');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4332');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-4333');
script_set_attribute(attribute: 'see_also', value: 'http://www.wireshark.org/security/wnpa-sec-2006-02.html');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200608-26.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200608-26] Wireshark: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Wireshark: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-analyzer/wireshark", unaffected: make_list("ge 0.99.3"), vulnerable: make_list("lt 0.99.3")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
