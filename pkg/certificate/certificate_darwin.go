//go:build darwin

package certificate

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
)

func fetchCertificates() ([]Certificate, error) {
	// 使用 -p 输出 PEM 格式，自行解析以获取准确的 thumbprint 和 CN
	cmd := exec.Command("security", "find-certificate", "-a", "-p")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("获取证书时发生错误: %w", err)
	}
	var certificates []Certificate
	data := output
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		thumbprint := fmt.Sprintf("%X", sha1.Sum(cert.Raw))
		certificates = append(certificates, Certificate{
			Thumbprint: thumbprint,
			Subject: CertificateSubject{
				CN: cert.Subject.CommonName,
				OU: cert.Subject.OrganizationalUnit[0],
				O:  cert.Subject.Organization[0],
				L:  cert.Subject.Locality[0],
				S:  cert.Subject.Province[0],
				C:  cert.Subject.Country[0],
			},
		})
	}
	return certificates, nil
}

func installCertificate(cert_data []byte) error {
	cert_file, err := os.CreateTemp("", "*.cer")
	if err != nil {
		return fmt.Errorf("没有创建证书的权限: %w", err)
	}
	defer os.Remove(cert_file.Name())
	if _, err := cert_file.Write(cert_data); err != nil {
		return fmt.Errorf("写入证书失败: %w", err)
	}
	if err := cert_file.Close(); err != nil {
		return fmt.Errorf("关闭证书文件失败: %w", err)
	}
	cmd := fmt.Sprintf("security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db '%s'", cert_file.Name())
	ps := exec.Command("bash", "-c", cmd)
	output, err2 := ps.CombinedOutput()
	if err2 != nil {
		return fmt.Errorf("安装证书时发生错误: %w, 输出: %s", err2, string(output))
	}
	return nil
}

func uninstallCertificate(certificate_name string) error {
	// 先从用户 login keychain 删除
	cmd := exec.Command("bash", "-c", fmt.Sprintf("security delete-certificate -c '%s'", certificate_name))
	output, err := cmd.CombinedOutput()
	// 再尝试从 System keychain 删除（旧版 SunnyNet 可能安装在此处）
	_ = exec.Command("bash", "-c", fmt.Sprintf("security delete-certificate -c '%s' -k /Library/Keychains/System.keychain", certificate_name)).Run()
	if err != nil {
		return fmt.Errorf("删除证书时发生错误: %w, 输出: %s", err, string(output))
	}
	return nil
}
