package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/urfave/cli"

	"github.com/dustin/go-humanize"
	"pault.ag/go/piv"
)

func loadCerts(path string) (*x509.CertPool, *x509.CertPool, error) {
	rootsPool := x509.NewCertPool()
	intPool := x509.NewCertPool()

	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	var p *pem.Block
	for {
		p, bytes = pem.Decode(bytes)
		if len(bytes) == 0 {
			break
		}

		if p == nil {
			return nil, nil, fmt.Errorf("certdump: invalid ca bundle")
		}

		if strings.Compare(p.Type, "CERTIFICATE") != 0 {
			return nil, nil, fmt.Errorf("certdump: pem chain has a non-cert in it")
		}

		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, nil, err
		}

		if !cert.IsCA {
			return nil, nil, fmt.Errorf("certdump: cert in ca bundle isn't a ca")
		}

		if cert.CheckSignatureFrom(cert) == nil {
			rootsPool.AddCert(cert)
		} else {
			intPool.AddCert(cert)
		}
	}

	return rootsPool, intPool, nil
}

func loadCert(path string) (*x509.Certificate, string, error) {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	format := "der"

	if bytes[0] == '-' && bytes[1] == '-' {
		/* attempt to try it as pem */
		block, _ := pem.Decode(bytes)
		bytes = block.Bytes
		format = "pem"
	}

	c, err := x509.ParseCertificate(bytes)
	return c, format, err
}

func ohshit(err error) {
	if err != nil {
		panic(err)
	}
}

func printCert(cert *piv.Certificate) {

	fmt.Printf("Certificate:\n")
	fmt.Printf("    Version:             %d\n", cert.Version)
	fmt.Printf("    Serial Number:       %d (0x%x)\n", cert.SerialNumber, cert.SerialNumber)
	fmt.Printf("    Signature Algorithm: %s\n", cert.SignatureAlgorithm)
	fmt.Printf("\n")

	fmt.Printf(`    Validity:
        Not Before: %s
                    (%s)
        Not After:  %s
                    (%s)
`,
		humanize.Time(cert.NotBefore),
		cert.NotBefore,
		humanize.Time(cert.NotAfter),
		cert.NotAfter,
	)
	fmt.Printf("\n")
	fmt.Printf("    Subject: %s\n", cert.Subject.String())

	for _, el := range cert.Subject.Names {
		fmt.Printf("             %s: %s\n", el.Type, el.Value)
	}
	fmt.Printf("\n")

	fmt.Printf("    Issuer: %s\n", cert.Issuer.String())
	fmt.Printf("\n")

	if cert.CompletedNACI != nil {
		fmt.Printf("    Cardholder NACI Completed at time of issuance: %t\n",
			*cert.CompletedNACI)
		fmt.Printf("\n")
	}

	if len(cert.FASCs) != 0 {
		for _, fasc := range cert.FASCs {
			fmt.Printf("    FASC:\n")
			fmt.Printf("        Issuing Agency:              %s (%d)\n",
				fasc.AgencyCode.String(), fasc.AgencyCode)
			fmt.Printf("        System Code:                 %d\n", fasc.SystemCode)
			fmt.Printf("        Credential:                  %d\n", fasc.Credential)
			fmt.Printf("        CredentialSeries:            %d\n", fasc.CredentialSeries)
			fmt.Printf("        IndidvidualCredentialSeries: %d\n", fasc.IndidvidualCredentialSeries)
			fmt.Printf("        PersonIdentifier:            %d\n", fasc.PersonIdentifier)
			fmt.Printf("        OrganizationCategory:        %s (%d)\n",
				fasc.OrganizationCategory.String(), fasc.OrganizationCategory)
			fmt.Printf("        Cardholder Agency:           %s (%d)\n",
				fasc.OrganizationIdentifier, fasc.OrganizationIdentifier)
			fmt.Printf("        Person Association:          %s (%d)\n",
				fasc.PersonAssociation, fasc.PersonAssociation)
			fmt.Printf("\n")
		}
	}

	fmt.Printf("    Public Key:\n")
	fmt.Printf("        Algorithm: %s\n", cert.PublicKeyAlgorithm)

	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		pk := cert.PublicKey.(*rsa.PublicKey)
		fmt.Printf("        RSA Information:\n")
		fmt.Printf("            Bits:     %d\n", pk.Size()*8)
		fmt.Printf("            Modulus:  %s\n", hexDump(pk.N.Bytes(), 20, 22, false))
		fmt.Printf("            Exponent: %x\n", pk.E)
		break
	default:
		fmt.Printf("        !!! OH CRAP I DON'T KNOW WHAT TO DO !!\n")
	}
	fmt.Printf("\n")

	// cert.KeyUsage
	// cert.ExtKeyUsage

	if cert.BasicConstraintsValid {
		fmt.Printf("    IsCA:            %t\n", cert.IsCA)
		fmt.Printf("    MaxPathLen:      %d\n", cert.MaxPathLen)
	}

	fmt.Printf("    SubjectKeyId:     %x\n", cert.SubjectKeyId)
	fmt.Printf("    AuthorityKeyID:   %x\n", cert.AuthorityKeyId)

	fmt.Printf("\n")

	maybePrint("OCSP Servers", cert.OCSPServer)
	maybePrint("Issuing Certificate URL", cert.IssuingCertificateURL)
	maybePrint("DNS Names", cert.DNSNames)
	maybePrint("EmailAddresses", cert.EmailAddresses)
	maybePrint("Principal Names", cert.PrincipalNames)

	if len(cert.IPAddresses) != 0 {
		fmt.Printf("    IP Addresses:\n")
		for _, el := range cert.IPAddresses {
			fmt.Printf("        %s\n", el.String())
		}
		fmt.Printf("\n")
	}

	if len(cert.URIs) != 0 {
		fmt.Printf("    URIs:\n")
		for _, el := range cert.URIs {
			fmt.Printf("        %s\n", el.String())
		}
		fmt.Printf("\n")
	}

	maybePrint("CRLs", cert.CRLDistributionPoints)

	if len(cert.PolicyIdentifiers) != 0 {
		fmt.Printf("    Policy Identifiers:\n")
		for _, el := range cert.PolicyIdentifiers {
			fmt.Printf("        %s\n", el.String())
		}
		fmt.Printf("\n")
	}

}

func maybePrint(name string, els []string) {
	if len(els) != 0 {
		fmt.Printf("    %s:\n", name)
		for _, el := range els {
			fmt.Printf("        %s\n", el)
		}
		fmt.Printf("\n")
	}
}

//
func hexDump(els []byte, perLine, indent uint, startIndent bool) string {
	ret := []string{}
	max := uint(len(els))

	var i uint = 0
	for ; i < uint(len(els)); i = i + perLine {
		start := i
		end := i + perLine
		if end > max {
			end = max
		}

		indentString := strings.Repeat(" ", int(indent))
		if i == 0 && !startIndent {
			indentString = ""
		}

		vals := els[start:end]
		ret = append(ret,
			fmt.Sprintf("%s%x", indentString, vals))
	}
	return strings.Join(ret, "\n")
}

func main() {
	app := cli.NewApp()
	app.Name = "certdump"
	app.Usage = "dump certs"
	app.Action = Main

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "ca",
			Value:  "",
			EnvVar: "CERTDUMP_CA_FILEPATH",
			Usage:  "path on the filesystem to a file full of pem CAs",
		},

		cli.BoolTFlag{
			Name:  "text",
			Usage: "output text from inside the cert",
		},

		cli.BoolTFlag{
			Name:  "validate",
			Usage: "validate cert and print chains",
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}

func printChain(roots, ints *x509.CertPool, cert *x509.Certificate) {
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: ints,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		fmt.Printf("Can't verify Certificate: %s\n", err)
		fmt.Printf("\n")
	}

	for i, chain := range chains {
		fmt.Printf("Chain %d\n", i)
		for i := 0; i < len(chain); i++ {
			cert := chain[len(chain)-(i+1)]

			indentString := strings.Repeat(" ", i*2) + "└"
			if i == 0 {
				indentString = "•"
			}

			what := ""
			if cert.IsCA {
				what = "authority"
			} else {
				usages := []string{}

				switch {
				case cert.KeyUsage&x509.KeyUsageDigitalSignature != 0:
					usages = append(usages, "signature")
				case cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0:
					usages = append(usages, "key-exchange")
				}
				for _, usage := range cert.ExtKeyUsage {
					switch usage {
					case x509.ExtKeyUsageServerAuth:
						usages = append(usages, "server")
					case x509.ExtKeyUsageClientAuth:
						usages = append(usages, "client")
					case x509.ExtKeyUsageEmailProtection:
						usages = append(usages, "s/mime")
					}
				}
				what = strings.Join(usages, ", ")
			}

			fmt.Printf(
				"%s %s (%s)\n",
				indentString,
				cert.Subject.CommonName,
				what,
			)
		}
		fmt.Printf("\n")
	}

}

func Main(c *cli.Context) {
	caFilePath := c.String("ca")
	if len(caFilePath) == 0 {
		cli.ShowAppHelpAndExit(c, 1)
	}

	validate := c.Bool("validate")
	text := c.Bool("text")

	roots, ints, err := loadCerts(caFilePath)
	ohshit(err)

	for _, path := range c.Args() {
		fmt.Printf("%s\n", path)

		cert, format, err := loadCert(path)
		if err != nil {
			log.Printf("Error loading %s formated cert: %s\n", format, err)
			continue
		}
		fmt.Printf("Certificate format: %s\n\n", format)

		if validate {
			printChain(roots, ints, cert)
		}

		if text {
			pcert, err := piv.NewCertificate(cert)
			if err != nil {
				log.Printf("Error parsing PIV: %s\n", err)
				continue
			}
			printCert(pcert)
		}
	}
}
