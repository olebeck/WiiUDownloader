package main

import (
	"context"
	"flag"
	"sync"

	wiiudownloader "github.com/Xpl0itU/WiiUDownloader"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
)

func main() {
	logger, _ := wiiudownloader.NewLogger("log.txt")

	var outputDir string
	flag.StringVar(&outputDir, "output", "out", "output dir")
	flag.Parse()

	if outputDir == "" {
		flag.PrintDefaults()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	entries := wiiudownloader.GetTitleEntries(wiiudownloader.TITLE_CATEGORY_ALL)

	p := mpb.New()
	prog := p.AddBar(int64(len(entries)),
		mpb.PrependDecorators(
			decor.Name("wiiu", decor.WC{C: decor.DindentRight | decor.DextraSpace}),
			decor.Name("downloading", decor.WCSyncSpaceR),
			decor.CountersNoUnit("%d / %d", decor.WCSyncWidth),
		),
		mpb.AppendDecorators(decor.Percentage()),
	)

	//var totalSize atomic.Int64
	var wg sync.WaitGroup
	entriesChan := make(chan wiiudownloader.TitleEntry)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for title := range entriesChan {
				/*
					size, err := wiiudownloader.GetTitleSize(ctx, title)
					if err != nil {
						logger.Error("error: %s\n", err)
						continue
					}
					totalSize.Add(int64(size))
				*/

				err := wiiudownloader.DownloadTitle(ctx, title, outputDir, p, logger)
				if err != nil {
					logger.Error("error: %d %s\n", title.TitleID, err)
					continue
				}
				prog.IncrBy(1)
			}
		}()
	}

	for _, entry := range entries {
		entriesChan <- entry
	}
	close(entriesChan)
	wg.Wait()

	//fmt.Printf("total: %d\n", totalSize.Load())
}
