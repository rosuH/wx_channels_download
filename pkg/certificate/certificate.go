package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type CertFileAndKeyFile struct {
	Name       string
	Cert       []byte
	PrivateKey []byte
}

type CertificateSubject struct {
	// label
	CN string
	// cenc
	OU string
	// hpky
	O string
	// hpky
	L string
	// subj
	S string
	// cenc
	C string
}

type Certificate struct {
	Thumbprint string
	Subject    CertificateSubject
}

// GenerateCA 动态生成唯一 CA 证书对
func GenerateCA(name string) (*CertFileAndKeyFile, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         name,
			Organization:       []string{name},
			OrganizationalUnit: []string{name},
			Country:            []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return &CertFileAndKeyFile{
		Name:       name,
		Cert:       certPEM,
		PrivateKey: keyPEM,
	}, nil
}

// GetOrGenerateCert 获取或生成证书
// 如果 dir 目录下已存在 ca.crt 和 ca.key，则读取复用
// 否则生成新证书并保存到该目录
func GetOrGenerateCert(dir, name string) (*CertFileAndKeyFile, error) {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	if certData, err := os.ReadFile(certPath); err == nil {
		if keyData, err := os.ReadFile(keyPath); err == nil {
			return &CertFileAndKeyFile{
				Name:       name,
				Cert:       certData,
				PrivateKey: keyData,
			}, nil
		}
	}

	cert, err := GenerateCA(name)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create cert dir: %w", err)
	}
	if err := os.WriteFile(certPath, cert.Cert, 0644); err != nil {
		return nil, fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, cert.PrivateKey, 0600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}

	return cert, nil
}

// 获取所有证书
func FetchCertificates() ([]Certificate, error) {
	return fetchCertificates()
}

// 根据名称检查是否存在指定证书
func CheckHasCertificate(cert_name string) (bool, error) {
	certificates, err := fetchCertificates()
	if err != nil {
		return false, err
	}
	for _, cert := range certificates {
		if cert.Subject.CN == cert_name {
			return true, nil
		}
	}
	return false, nil
}

// 安装指定证书
func InstallCertificate(cert_data []byte) error {
	return installCertificate(cert_data)
}

// 卸载指定证书
func UninstallCertificate(name string) error {
	return uninstallCertificate(name)
}
