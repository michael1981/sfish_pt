# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-14.xml
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
 script_id(29734);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200712-14");
 script_cve_id("CVE-2007-4045", "CVE-2007-5849", "CVE-2007-6358");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-14 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-14
(CUPS: Multiple vulnerabilities)


    Wei Wang (McAfee AVERT Research) discovered an integer underflow in the
    asn1_get_string() function of the SNMP backend, leading to a
    stack-based buffer overflow when handling SNMP responses
    (CVE-2007-5849). Elias Pipping (Gentoo) discovered that the alternate
    pdftops filter creates temporary files with predictable file names when
    reading from standard input (CVE-2007-6358). Furthermore, the
    resolution of a Denial of Service vulnerability covered in GLSA
    200703-28 introduced another Denial of Service vulnerability within SSL
    handling (CVE-2007-4045).
  
Impact

    A remote attacker on the local network could exploit the first
    vulnerability to execute arbitrary code with elevated privileges by
    sending specially crafted SNMP messages as a response to an SNMP
    broadcast request. A local attacker could exploit the second
    vulnerability to overwrite arbitrary files with the privileges of the
    user running the CUPS spooler (usually lp) by using symlink attacks. A
    remote attacker could cause a Denial of Service condition via the third
    vulnerability when SSL is enabled in CUPS.
  
Workaround

    To disable SNMP support in CUPS, you have have to manually delete the
    file "/usr/libexec/cups/backend/snmp". Please note that the file is
    reinstalled if you merge CUPS again later. To disable the pdftops
    filter, delete all lines referencing "pdftops" in CUPS\' "mime.convs"
    configuration file. To work around the third vulnerability, disable SSL
    support via the corresponding USE flag.
  
');
script_set_attribute(attribute:'solution', value: '
    All CUPS users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-print/cups-1.2.12-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4045');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5849');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6358');
script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200703-28.xml');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-14.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-14] CUPS: Multiple vulnerabilities');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'CUPS: Multiple vulnerabilities');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-print/cups", unaffected: make_list("rge 1.2.12-r4", "ge 1.3.5"), vulnerable: make_list("lt 1.3.5")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
