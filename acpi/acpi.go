package acpi

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/tinfoilsh/tfshim/config"
)

func HandleQemuACPI(externalConfig *config.ExternalConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if externalConfig.ACPIAPIKey != "" {
			apiKey := strings.TrimPrefix(
				r.Header.Get("Authorization"),
				"Bearer ",
			)
			if apiKey != externalConfig.ACPIAPIKey {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
		}

		type acpi_file struct {
			Path string
			Name string
		}
		acpi_files := []acpi_file{
			{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/acpi/tables/raw", Name: "acpi_tables.bin"},
			{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/acpi/rsdp/raw", Name: "rsdp.bin"},
			{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/table-loader/raw", Name: "table_loader.bin"},
		}

		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		defer tw.Close()

		for _, af := range acpi_files {
			data, err := os.ReadFile(af.Path)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to read ACPI source file %s", af.Name), http.StatusInternalServerError)
				return
			}
			hdr := &tar.Header{
				Name: af.Name,
				Mode: 0600,
				Size: int64(len(data)),
			}
			if err := tw.WriteHeader(hdr); err != nil {
				http.Error(w, fmt.Sprintf("Failed to write header for ACPI source file %s", af.Name), http.StatusInternalServerError)
				return
			}
			if _, err := tw.Write(data); err != nil {
				http.Error(w, fmt.Sprintf("Failed to write ACPI source file %s", af.Name), http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Disposition", "attachment; filename=\"acpi.tar\"")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Encoding", "identity")

		if _, err := io.Copy(w, &buf); err != nil {
			http.Error(w, fmt.Sprintf("Failed to copy ACPI archive to response: %v", err), http.StatusInternalServerError)
			return
		}

	}
}
