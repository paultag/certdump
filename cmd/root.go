package cmd

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"pault.ag/go/piv"
	"pault.ag/go/technicolor"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use: "certdump",
	RunE: func(cmd *cobra.Command, args []string) error {
		flags := cmd.Flags()

		caFilePath, err := flags.GetString("ca")
		if err != nil {
			return err
		}

		validate, err := flags.GetBool("validate")
		if err != nil {
			return err
		}

		text, err := flags.GetBool("text")
		if err != nil {
			return err
		}

		outputJson, err := flags.GetBool("json")
		if err != nil {
			return err
		}

		quiet := false
		if outputJson {
			quiet = true
			text = false
			validate = false
		}

		roots := x509.NewCertPool()
		ints := x509.NewCertPool()

		if len(caFilePath) != 0 {
			roots, ints, err = loadCerts(caFilePath)
			ohshit(err)
		}

		output := technicolor.NewTerminalWriter(os.Stdout)

		for _, path := range args {
			if !quiet {
				fmt.Printf("%s\n", path)
			}

			cert, format, err := loadCert(path)
			if err != nil {
				output.Red().Bold().Printf(
					"Error loading %s formated cert: %s\n", format, err)
				output.ResetColor().Write([]byte{})
				continue
			}
			if !quiet {
				fmt.Printf("\nCertificate format: %s\n\n", format)
			}

			if validate {
				printChain(roots, ints, cert)
			}

			pcert, err := piv.NewCertificate(cert)
			if err != nil {
				log.Printf("Error parsing PIV: %s\n", err)
				continue
			}

			if text {
				printCert(pcert)
			}

			if outputJson {
				ohshit(json.NewEncoder(os.Stdout).Encode(pcert))
			}

		}
		return nil
	},
}

func init() {
	flags := rootCmd.Flags()
	flags.String("ca", "", "CA Bundle to use to validate the Certificate")
	flags.Bool("validate", true, "validate the certificate")
	flags.Bool("text", true, "output the cert in a human readable format")
	flags.Bool("json", false, "output the cert as json")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

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

		if len(bytes) == 0 {
			break
		}
	}

	return rootsPool, intPool, nil
}

func printTime(name string, when time.Time, color bool) {
	fmt.Printf("           %s:", name)
	output := technicolor.NewTerminalWriter(os.Stdout)

	diff := when.Sub(time.Now())

	if color {
		switch {
		case diff < 0:
			output = output.Bold().Red()
		case diff < (time.Hour * 720):
			output = output.Yellow()
		case diff > 0:
			output = output.Green()
		}
	}

	output.Printf(` %s
	              %s
`, humanize.Time(when), when)

	output.ResetColor().Write([]byte{})
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

	fmt.Printf("    Validity:\n")

	printTime("Not Before", cert.NotBefore, false)
	printTime("Not After", cert.NotAfter, true)

	fmt.Printf("\n")
	fmt.Printf("    Subject: %s\n", cert.Subject.String())

	for _, el := range cert.Subject.Names {
		elName := el.Type.String()

		names := map[string]string{
			"0.9.2342.19200300.100.1.1": "user id",
			"1.3.6.1.4.1.12348.1.1":     "ham callsign",
			"1.2.840.113549.1.9.1":      "email",
		}

		for k, v := range names {
			if strings.Compare(elName, k) == 0 {
				elName = fmt.Sprintf("%s (%s)", elName, v)
			}
		}

		fmt.Printf("             %s: %s\n", elName, el.Value)
	}
	fmt.Printf("\n")

	fmt.Printf("    Issuer: %s\n", cert.Issuer.String())
	fmt.Printf("\n")

	if cert.CompletedNACI != nil {
		fmt.Printf("    Cardholder NACI Completed at time of issuance: %t\n",
			*cert.CompletedNACI)
		fmt.Printf("\n")
	}

	fmt.Printf("    PKI Policies\n")
	fmt.Printf("        Highest LOA: %s\n\n", cert.Policies.HighestAssurance())
	if len(cert.Policies) != 0 {
		for _, policy := range cert.Policies {
			fmt.Printf("        %s:\n", policy.Name)
			fmt.Printf("          OID:      %s\n", policy.ID.String())
			fmt.Printf("          Person:   %t\n", policy.Issued.Person)

			output := technicolor.NewTerminalWriter(os.Stdout)
			if policy.Issued.Hardware {
				output = output.Green()
			} else {
				output = output.Red().Bold()
			}
			output.Printf("          Hardware: %t", policy.Issued.Hardware)
			output.ResetColor().Write([]byte("\n"))

			switch policy.Issued.AssuranceLevel {
			case piv.RudimentaryAssurance:
				output = output.Red().Bold()
			case piv.BasicAssurance:
				output = output.Red()
			case piv.MediumAssurance:
				output = output.Green()
			case piv.HighAssurance:
				output = output.Green().Bold()
			}
			output.Printf("          LOA:      %s\n", policy.Issued.AssuranceLevel)
			output.ResetColor().Write([]byte("\n"))

			fmt.Printf("\n")
		}
	} else {
		fmt.Printf("    No PIV PKI Policies found!\n")
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

	fmt.Printf("    Present Extensions:\n")
	name := "unknown"
	for _, extension := range cert.Extensions {
		switch {
		case extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 14}):
			name = "subject key id"
		case extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}):
			name = "key usage"
		case extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}):
			name = "extended key usage"
		case extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}):
			name = "authority key id"
		case extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 19}):
			name = "basic constraints"
		case extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}):
			name = "subject alt name"
		case extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 32}):
			name = "policies"
		case extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 30}):
			name = "name constraint"
		case extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 31}):
			name = "crl distribution points"
		case extension.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}):
			name = "authority info"
		}
		fmt.Printf("        %s (%s)\n", extension.Id, name)
	}
	fmt.Printf("\n")
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

func printChain(roots, ints *x509.CertPool, cert *x509.Certificate) {
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: ints,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	output := technicolor.NewTerminalWriter(os.Stdout)
	if err != nil {
		output.Red().Bold().Printf(
			"Can't verify Certificate: %s\n", err)
	} else {
		output.Green().Printf("Certificate is valid!\n")
	}
	output.ResetColor().Write([]byte("\n"))

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
				" %s %s (%s)\n",
				indentString,
				cert.Subject.CommonName,
				what,
			)
		}
		fmt.Printf("\n")
	}

}
