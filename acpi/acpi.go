package acpi

import (
	"archive/tar"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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

		type src struct {
			Path string
			Name string
		}
		candidates := []src{
			{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/acpi/tables/raw", Name: "acpi_tables.bin"},
			{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/acpi/rsdp/raw", Name: "rsdp.bin"},
			{Path: "/sys/firmware/qemu_fw_cfg/by_name/etc/table-loader/raw", Name: "table_loader.bin"},
		}

		var sources []src
		for _, c := range candidates {
			if fi, err := os.Stat(c.Path); err == nil && !fi.IsDir() {
				sources = append(sources, c)
			}
		}
		if len(sources) != 3 {
			http.Error(w, "ACPI files not (all) found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/x-tar")
		w.Header().Set("Content-Disposition", "attachment; filename=\"acpi.tar\"")
		w.Header().Set("Cache-Control", "no-store")

		tw := tar.NewWriter(w)
		defer tw.Close()

		now := time.Now()
		for _, s := range sources {
			fi, err := os.Stat(s.Path)
			if err != nil {
				http.Error(w, "Failed to stat source file", http.StatusInternalServerError)
				return
			}
			f, err := os.Open(s.Path)
			if err != nil {
				http.Error(w, "Failed to open source file", http.StatusInternalServerError)
				return
			}

			hdr := &tar.Header{
				Name:    filepath.ToSlash(s.Name),
				Mode:    0600,
				Size:    fi.Size(),
				ModTime: now,
			}
			if err := tw.WriteHeader(hdr); err != nil {
				f.Close()
				http.Error(w, "Failed to write tar header", http.StatusInternalServerError)
				return
			}
			if _, err := io.Copy(tw, f); err != nil {
				f.Close()
				http.Error(w, "Failed to stream tar content", http.StatusInternalServerError)
				return
			}
			f.Close()
		}
	}
}
