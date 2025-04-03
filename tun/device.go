package tun

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"

	"vibepn/log"

	"github.com/songgao/water"
)

type Device struct {
	iface *water.Interface
	name  string
	log   *log.Logger
}

func Open(cidr string, nodeID string) (*Device, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}

	base := iface.Name()

	// Hash nodeID to create deterministic suffix
	h := sha256.Sum256([]byte(nodeID))
	suffix := hex.EncodeToString(h[:])[:6]
	newName := fmt.Sprintf("vibepn-%s", suffix)

	if err := renameInterface(base, newName); err != nil {
		return nil, fmt.Errorf("failed to rename %s to %s: %w", base, newName, err)
	}

	dev := &Device{
		iface: iface,
		name:  newName,
		log:   log.New("tun/" + newName),
	}

	dev.log.Infof("Created TUN device %s (from %s)", newName, base)

	if err := dev.configureIP(cidr); err != nil {
		return nil, fmt.Errorf("failed to configure IP: %w", err)
	}

	return dev, nil
}

func renameInterface(oldName, newName string) error {
	cmd := exec.Command("ip", "link", "set", oldName, "name", newName)
	return cmd.Run()
}

func (d *Device) configureIP(cidr string) error {
	cmd := exec.Command("ip", "addr", "add", cidr, "dev", d.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to assign IP: %w", err)
	}

	cmd = exec.Command("ip", "link", "set", "up", "dev", d.name)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	d.log.Infof("Configured %s with CIDR %s", d.name, cidr)
	return nil
}

func (d *Device) Read(buf []byte) (int, error) {
	return d.iface.Read(buf)
}

func (d *Device) Write(pkt []byte) (int, error) {
	return d.iface.Write(pkt)
}

func (d *Device) Close() error {
	return d.iface.Close()
}

func (d *Device) Name() string {
	return d.name
}
