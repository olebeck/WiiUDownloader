package wiiudownloader

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

const (
	maxRetries = 5
	retryDelay = 5 * time.Second
	bufferSize = 1048576
)

func calculateDownloadSpeed(downloaded int64, startTime, endTime time.Time) int64 {
	duration := endTime.Sub(startTime).Seconds()
	if duration > 0 {
		return int64(float64(downloaded) / duration)
	}
	return 0
}

func newBar(name string, p *mpb.Progress) *mpb.Bar {
	return p.AddBar(0,
		mpb.BarRemoveOnComplete(),
		mpb.PrependDecorators(
			decor.Name(name, decor.WC{C: decor.DindentRight | decor.DextraSpace}),
			decor.Counters(decor.SizeB1024(0), "% .2f / % .2f"),
		),
		mpb.AppendDecorators(
			decor.EwmaETA(decor.ET_STYLE_GO, 30),
			decor.Name(" ] "),
			decor.EwmaSpeed(decor.SizeB1024(0), "% .2f", 60),
		),
	)
}

func downloadFile(ctx context.Context, bar *mpb.Bar, newTotal bool, downloadURL, dstPath string, doRetries bool) error {
	req, err := http.NewRequest("GET", downloadURL, nil)
	if err != nil {
		return err
	}
	retries := 0
retry:
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if doRetries && retries < maxRetries {
			fmt.Printf("retrying %+v\n", err)
			retries += 1
			goto retry
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("status " + resp.Status)
	}

	f, _ := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY, 0644)
	defer f.Close()
	if newTotal {
		bar.SetTotal(resp.ContentLength, false)
	}
	var proxyReader io.ReadCloser = resp.Body
	if bar != nil {
		proxyReader = bar.ProxyReader(resp.Body)
		defer proxyReader.Close()
	}

	_, err = io.Copy(f, proxyReader)
	if err != nil {
		if doRetries && retries < maxRetries {
			fmt.Printf("retrying %+v\n", err)
			retries += 1
			goto retry
		}
	}
	return err
}

func DownloadTitle(cancelCtx context.Context, titleEntry TitleEntry, outputDir string, p *mpb.Progress, logger *Logger) error {
	defer func() {
		if err := recover(); err != nil {
			logger.Error("panic %d %s\n", titleEntry.TitleID, err)
		}
	}()

	titleID := fmt.Sprintf("%016x", titleEntry.TitleID)
	prog := newBar(titleEntry.Name, p)

	outputDir = strings.TrimRight(outputDir, "/\\")
	outputDir = filepath.Join(outputDir, titleID)

	if f, err := os.Open(filepath.Join(outputDir, "title.json")); err == nil {
		f.Close()
		prog.SetTotal(0, true)
		return nil
	}

	baseURL := fmt.Sprintf("http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/%s", titleID)
	titleIDBytes, err := hex.DecodeString(titleID)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		return err
	}

	tmdPath := filepath.Join(outputDir, "title.tmd")
	if err := downloadFile(cancelCtx, nil, false, fmt.Sprintf("%s/%s", baseURL, "tmd"), tmdPath, true); err != nil {
		return err
	}

	tmdData, err := os.ReadFile(tmdPath)
	if err != nil {
		return err
	}

	var titleVersion uint16
	if err := binary.Read(bytes.NewReader(tmdData[476:478]), binary.BigEndian, &titleVersion); err != nil {
		return err
	}

	tikPath := filepath.Join(outputDir, "title.tik")
	if err := downloadFile(cancelCtx, nil, false, fmt.Sprintf("%s/%s", baseURL, "cetk"), tikPath, false); err != nil {
		titleKey, err := GenerateKey(titleID)
		if err != nil {
			return err
		}
		if err := GenerateTicket(tikPath, titleEntry.TitleID, titleKey, titleVersion); err != nil {
			return err
		}
	}
	tikData, err := os.ReadFile(tikPath)
	if err != nil {
		return err
	}
	encryptedTitleKey := tikData[0x1BF : 0x1BF+0x10]

	var contentCount uint16
	if err := binary.Read(bytes.NewReader(tmdData[478:480]), binary.BigEndian, &contentCount); err != nil {
		return err
	}

	var titleSize uint64
	var contentSizes []uint64
	for i := 0; i < int(contentCount); i++ {
		contentDataLoc := 0xB04 + (0x30 * i)

		var contentSizeInt uint64
		if err := binary.Read(bytes.NewReader(tmdData[contentDataLoc+8:contentDataLoc+8+8]), binary.BigEndian, &contentSizeInt); err != nil {
			return err
		}

		titleSize += contentSizeInt
		contentSizes = append(contentSizes, contentSizeInt)
	}

	prog.SetTotal(int64(titleSize), false)

	cert, err := GenerateCert(tmdData, contentCount, cancelCtx)
	if err != nil {
		return err
	}

	certPath := filepath.Join(outputDir, "title.cert")
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	if err := binary.Write(certFile, binary.BigEndian, cert.Bytes()); err != nil {
		return err
	}
	defer certFile.Close()
	logger.Info("Certificate saved to %v \n", certPath)

	c, err := aes.NewCipher(commonKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	decryptedTitleKey := make([]byte, len(encryptedTitleKey))
	cbc := cipher.NewCBCDecrypter(c, append(titleIDBytes, make([]byte, 8)...))
	cbc.CryptBlocks(decryptedTitleKey, encryptedTitleKey)

	cipherHashTree, err := aes.NewCipher(decryptedTitleKey)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	var id uint32
	var content contentInfo
	tmdDataReader := bytes.NewReader(tmdData)

	for i := 0; i < int(contentCount); i++ {
		offset := 2820 + (48 * i)
		tmdDataReader.Seek(int64(offset), 0)
		if err := binary.Read(tmdDataReader, binary.BigEndian, &id); err != nil {
			return err
		}
		filePath := filepath.Join(outputDir, fmt.Sprintf("%08X.app", id))
		if err := downloadFile(cancelCtx, prog, false, fmt.Sprintf("%s/%08X", baseURL, id), filePath, true); err != nil {
			return err
		}

		if tmdData[offset+7]&0x2 == 2 {
			filePath = filepath.Join(outputDir, fmt.Sprintf("%08X.h3", id))
			if err := downloadFile(cancelCtx, nil, false, fmt.Sprintf("%s/%08X.h3", baseURL, id), filePath, true); err != nil {
				return err
			}
			content.Hash = tmdData[offset+16 : offset+0x14]
			content.ID = fmt.Sprintf("%08X", id)
			content.Size = int64(contentSizes[i])
			if err := checkContentHashes(outputDir, content, cipherHashTree); err != nil {
				return err
			}
		}
	}

	f, err := os.Create(filepath.Join(outputDir, "title.json"))
	if err != nil {
		return err
	}
	json.NewEncoder(f).Encode(&titleEntry)
	f.Close()
	prog.SetCurrent(int64(titleSize))

	return nil
}

func GetTitleSize(ctx context.Context, entry TitleEntry) (uint64, error) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("%s\n", err)
		}
	}()

	titleID := fmt.Sprintf("%016x", entry.TitleID)

	baseURL := fmt.Sprintf("http://ccs.cdn.c.shop.nintendowifi.net/ccs/download/%s", titleID)

	res, err := http.DefaultClient.Get(fmt.Sprintf("%s/%s", baseURL, "tmd"))
	if err != nil {
		return 0, err
	}
	tmdData, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil {
		return 0, err
	}

	var contentCount uint16
	if err := binary.Read(bytes.NewReader(tmdData[478:480]), binary.BigEndian, &contentCount); err != nil {
		return 0, err
	}

	var titleSize uint64
	var contentSizes []uint64
	for i := 0; i < int(contentCount); i++ {
		contentDataLoc := 0xB04 + (0x30 * i)

		var contentSizeInt uint64
		if err := binary.Read(bytes.NewReader(tmdData[contentDataLoc+8:contentDataLoc+8+8]), binary.BigEndian, &contentSizeInt); err != nil {
			return 0, err
		}

		titleSize += contentSizeInt
		contentSizes = append(contentSizes, contentSizeInt)
	}

	return titleSize, nil
}
