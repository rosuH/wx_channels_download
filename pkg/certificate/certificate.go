package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LegacySunnyNetThumbprint 是原仓库内嵌 SunnyNet 证书（公开私钥）的 SHA1 指纹
// 用于精确识别并清理旧版危险证书
const LegacySunnyNetThumbprint = "D70CD039051F77C30673B8209FC15EFA650ED52C"

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

	// 使用随机序列号，确保每次生成的证书唯一可区分
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
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

// GetCertThumbprint 计算证书 PEM 的 SHA1 指纹（大写无冒号）
func GetCertThumbprint(certPEM []byte) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	sum := sha1.Sum(cert.Raw)
	return fmt.Sprintf("%X", sum)
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

// FindCertificatesByName 根据名称查找系统中的所有证书，包含指纹信息
func FindCertificatesByName(certName string) ([]Certificate, error) {
	all, err := fetchCertificates()
	if err != nil {
		return nil, err
	}
	var matched []Certificate
	for _, cert := range all {
		if strings.EqualFold(cert.Subject.CN, certName) {
			matched = append(matched, cert)
		}
	}
	return matched, nil
}

// 安装指定证书
func InstallCertificate(cert_data []byte) error {
	return installCertificate(cert_data)
}

// 卸载指定证书
func UninstallCertificate(name string) error {
	return uninstallCertificate(name)
}
