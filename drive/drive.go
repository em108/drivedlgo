package drive

import (
	"drivedlgo/customdec"
	"drivedlgo/db"
	"drivedlgo/utils"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"
	"sort"
	"regexp"

	"github.com/fatih/color"
	"github.com/vbauerster/mpb/v8"

	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

var wg sync.WaitGroup

const MAX_NAME_CHARACTERS int = 17
const MAX_RETRIES int = 5

type GoogleDriveClient struct {
	GDRIVE_DIR_MIMETYPE string
	TokenFile           string
	CredentialFile      string
	DriveSrv            *drive.Service
	Progress            *mpb.Progress
	abuse               bool
	numFilesDownloaded  int
	channel             chan int
	sortOrder           string
	fileFilter          string

}

func (G *GoogleDriveClient) SetSortOrder(order string) {
	G.sortOrder = order
}

func (G *GoogleDriveClient) SetFileFilter(filter string) {
	G.fileFilter = filter
	fmt.Printf("File filter set to: %s\n", filter)
}

func (G *GoogleDriveClient) matchesFilter(fileName string) bool {
	if G.fileFilter == "" {
		return true
	}

	// Check if it's a file extension filter
	if strings.HasPrefix(G.fileFilter, ".") {
		return strings.HasSuffix(strings.ToLower(fileName), strings.ToLower(G.fileFilter))
	}

	// Try as a regular expression
	match, err := regexp.MatchString(G.fileFilter, fileName)
	if err == nil {
		return match
	}

	// If not a valid regex, treat as a substring
	return strings.Contains(strings.ToLower(fileName), strings.ToLower(G.fileFilter))
}

func (G *GoogleDriveClient) Init() {
	G.GDRIVE_DIR_MIMETYPE = "application/vnd.google-apps.folder"
	G.TokenFile = "token.json"
	G.CredentialFile = "credentials.json"
	G.channel = make(chan int, 2)
	G.Progress = mpb.New(mpb.WithWidth(60), mpb.WithRefreshRate(180*time.Millisecond))
}

func (G *GoogleDriveClient) SetAbusiveFileDownload(abuse bool) {
	fmt.Printf("Acknowledge-Abuse: %t\n", abuse)
	G.abuse = abuse
}

func (G *GoogleDriveClient) SetConcurrency(count int) {
	fmt.Printf("Using Concurrency: %d\n", count)
	G.channel = make(chan int, count)
}

func (G *GoogleDriveClient) PrepareProgressBar(size int64, dec decor.Decorator) *mpb.Bar {
	return G.Progress.AddBar(size,
		mpb.PrependDecorators(
			decor.Name("[ "),
			dec,
			decor.Name(" ] "),
			decor.CountersKibiByte("% .2f / % .2f"),
		),
		mpb.AppendDecorators(
			decor.AverageETA(decor.ET_STYLE_GO),
			decor.Name("]"),
			decor.AverageSpeed(decor.SizeB1000(0), " % .2f"),
		),
	)
}

func (G *GoogleDriveClient) GetProgressBar(filename string, size int64) *mpb.Bar {
	if len(filename) > MAX_NAME_CHARACTERS {
		marquee := customdec.NewChangeNameDecor(filename, MAX_NAME_CHARACTERS)
		return G.PrepareProgressBar(size, marquee.MarqueeText())
	}
	return G.PrepareProgressBar(size, decor.Name(filename, decor.WC{W: 5, C: decor.DSyncSpaceR}))
}

func (G *GoogleDriveClient) getClient(dbPath string, config *oauth2.Config, port int) *http.Client {
	tokBytes, err := db.GetTokenDb(dbPath)
	var tok *oauth2.Token
	if err != nil {
		tok = G.getTokenFromWeb(config, port)
		db.AddTokenDb(dbPath, utils.OauthTokenToBytes(tok))
	} else {
		tok = utils.BytesToOauthToken(tokBytes)
	}
	return config.Client(context.Background(), tok)
}

func (G *GoogleDriveClient) getTokenFromHTTP(port int) (string, error) {
	srv := &http.Server{Addr: fmt.Sprintf(":%d", port)}
	var code string
	var codeReceived chan struct{} = make(chan struct{})
	var err error
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code = r.URL.Query().Get("code")
		_, err = fmt.Fprint(w, "Code received, you can close this browser window now.")
		codeReceived <- struct{}{}
	})
	go func() {
		err = srv.ListenAndServe()
	}()
	if err != nil {
		return code, err
	}
	<-codeReceived
	err = srv.Shutdown(context.Background())
	return code, err
}

func (G *GoogleDriveClient) getTokenFromWeb(config *oauth2.Config, port int) *oauth2.Token {
	config.RedirectURL = fmt.Sprintf("http://localhost:%d", port)
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("Go to the following link in your browser: \n%v\n", authURL)
	err := utils.OpenBrowserURL(authURL)
	if err != nil {
		log.Printf("unable to open browser, you have to manually visit the provided link: %v\n", err)
	}
	authCode, err := G.getTokenFromHTTP(port)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("unable to get token from oauth web: %v\n", err)
	}
	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	return tok
}

func (G *GoogleDriveClient) Authorize(dbPath string, useSA bool, port int) {
	var client *http.Client
	if useSA {
		fmt.Println("Authorizing via service-account")
		jwtConfigJsonBytes, err := db.GetJWTConfigDb(dbPath)
		if err != nil {
			log.Fatalf("Unable to Get SA Credentials from Db, make sure to use setsa command: %v", err)
		}
		// If modifying these scopes, delete your previously saved token.json.
		config, err := google.JWTConfigFromJSON(jwtConfigJsonBytes, drive.DriveScope)
		if err != nil {
			log.Fatalf("Unable to parse client secret file to config: %v", err)
		}
		client = config.Client(context.Background())
	} else {
		fmt.Println("Authorizing via google-account")
		credsJsonBytes, err := db.GetCredentialsDb(dbPath)
		if err != nil {
			log.Fatalf("Unable to Get Credentials from Db, make sure to use set command: %v", err)
		}

		// If modifying these scopes, delete your previously saved token.json.
		config, err := google.ConfigFromJSON(credsJsonBytes, drive.DriveScope)
		if err != nil {
			log.Fatalf("Unable to parse client secret file to config: %v", err)
		}
		client = G.getClient(dbPath, config, port)
	}
	srv, err := drive.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		log.Fatalf("Unable to retrieve Drive client: %v", err)
	}
	G.DriveSrv = srv
}

func (G *GoogleDriveClient) GetFilesByParentId(parentId string) []*drive.File {
	var files []*drive.File
	pageToken := ""
	for {
		request := G.DriveSrv.Files.List().Q("'" + parentId + "' in parents and trashed=false").SupportsAllDrives(true).IncludeTeamDriveItems(true).PageSize(1000).
			Fields("nextPageToken,files(id, name, size, mimeType, md5Checksum)")
		if pageToken != "" {
			request = request.PageToken(pageToken)
		}
		res, err := request.Do()
		if err != nil {
			fmt.Printf("Error : %v", err)
			return files
		}
		files = append(files, res.Files...)
		pageToken = res.NextPageToken
		if pageToken == "" {
			break
		}
	}

	// Sort files based on the specified order
	G.sortFiles(files)

	return files
}

func (G *GoogleDriveClient) sortFiles(files []*drive.File) {
	// First, separate folders and non-folders
	var folders, nonFolders []*drive.File
	for _, file := range files {
		if file.MimeType == G.GDRIVE_DIR_MIMETYPE {
			folders = append(folders, file)
		} else {
			nonFolders = append(nonFolders, file)
		}
	}

	// Define a common sorting function
	sortFunc := func(slice []*drive.File) {
		switch G.sortOrder {
		case "name_asc":
			sort.Slice(slice, func(i, j int) bool {
				return slice[i].Name < slice[j].Name
			})
		case "name_desc":
			sort.Slice(slice, func(i, j int) bool {
				return slice[i].Name > slice[j].Name
			})
		case "size_asc":
			sort.Slice(slice, func(i, j int) bool {
				return slice[i].Size < slice[j].Size
			})
		case "size_desc":
			sort.Slice(slice, func(i, j int) bool {
				return slice[i].Size > slice[j].Size
			})
		default:
			// Default to name_asc if an invalid sort order is provided
			sort.Slice(slice, func(i, j int) bool {
				return slice[i].Name < slice[j].Name
			})
		}
	}

	// Sort folders and non-folders separately
	sortFunc(folders)
	sortFunc(nonFolders)

	// Combine folders and non-folders, with folders first
	copy(files, append(folders, nonFolders...))
}

func (G *GoogleDriveClient) GetFileMetadata(fileId string) *drive.File {
	file, err := G.DriveSrv.Files.Get(fileId).Fields("name,mimeType,size,id,md5Checksum").SupportsAllDrives(true).Do()
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	return file
}

func (G *GoogleDriveClient) Download(nodeId string, localPath string, outputPath string, numParts int) {
	startTime := time.Now()
	file := G.GetFileMetadata(nodeId)
	if outputPath == "" {
		outputPath = utils.CleanupFilename(file.Name)
	}
	fmt.Printf("%s(%s): %s -> %s/%s\n", color.HiBlueString("Download"), color.GreenString(file.MimeType), color.HiGreenString(file.Id), color.HiYellowString(localPath), color.HiYellowString(outputPath))
	absPath := path.Join(localPath, outputPath)
	if file.MimeType == G.GDRIVE_DIR_MIMETYPE {
		err := os.MkdirAll(absPath, 0755)
		if err != nil {
			fmt.Println("Error while creating directory: ", err.Error())
			return
		}
		files := G.GetFilesByParentId(file.Id)
		if len(files) == 0 {
			fmt.Println("google drive folder is empty.")
		} else {
			G.TraverseNodes(file.Id, absPath)
		}
	} else if G.matchesFilter(file.Name) {
		err := os.MkdirAll(localPath, 0755)
		if err != nil {
			fmt.Println("Error while creating directory: ", err.Error())
			return
		}
		G.channel <- 1
		wg.Add(1)
		go G.HandleDownloadFile(file, absPath, numParts)
	} else {
		fmt.Printf("Skipping file: %s (doesn't match filter)\n", file.Name)
	}
	wg.Wait()
	G.Progress.Wait()
	fmt.Printf("%s", color.GreenString(fmt.Sprintf("Downloaded %d files in %s.\n", G.numFilesDownloaded, time.Now().Sub(startTime))))
}

func (G *GoogleDriveClient) TraverseNodes(nodeId string, localPath string) {
	files := G.GetFilesByParentId(nodeId)
	for _, file := range files {
		absPath := path.Join(localPath, utils.CleanupFilename(file.Name))
		if file.MimeType == G.GDRIVE_DIR_MIMETYPE {
			err := os.MkdirAll(absPath, 0755)
			if err != nil {
				log.Printf("[DirectoryCreationError]: %v\n", err)
				continue
			}
			G.TraverseNodes(file.Id, absPath)
		} else if G.matchesFilter(file.Name) {
			G.channel <- 1
			wg.Add(1)
			go G.HandleDownloadFile(file, absPath, 1)
		} else {
			fmt.Printf("Skipping file: %s (doesn't match filter)\n", file.Name)
		}
	}
}

func (G *GoogleDriveClient) HandleDownloadFile(file *drive.File, absPath string, numParts int) {
	defer func() {
		wg.Done()
		<-G.channel
	}()

	exists, bytesDled, err := utils.CheckLocalFile(absPath, file.Md5Checksum)
	if err != nil {
		log.Printf("[FileCheckError]: %v\n", err)
		return
	}
	if exists {
		// Verify the file size of the existing file
		fileInfo, err := os.Stat(absPath)
		if err != nil {
			log.Printf("[FileStatError]: %v\n", err)
			G.restartDownload(file, absPath, numParts)
			return
		}
		if fileInfo.Size() != file.Size {
			log.Printf("Existing file size mismatch for %s. Expected: %d, Got: %d. Restarting download.\n", file.Name, file.Size, fileInfo.Size())
			G.restartDownload(file, absPath, numParts)
			return
		}
		// Verify MD5 checksum for completely downloaded files
		downloadedMD5, err := utils.GetFileMd5(absPath)
		if err != nil {
			log.Printf("[MD5VerificationError]: %v\n", err)
			G.restartDownload(file, absPath, numParts)
			return
		}
		if downloadedMD5 != file.Md5Checksum {
			log.Printf("MD5 checksum mismatch for %s. Expected: %s, Got: %s. Restarting download.\n", file.Name, file.Md5Checksum, downloadedMD5)
			G.restartDownload(file, absPath, numParts)
			return
		}
		fmt.Printf("%s already downloaded and verified.\n", file.Name)
		return
	}
	if bytesDled != 0 {
		o := fmt.Sprintf("Resuming %s at offset %d\n", file.Name, bytesDled)
		fmt.Printf("%s", color.GreenString(o))
	}
	success := G.DownloadFile(file, absPath, bytesDled, 1, numParts)
	if success {
		// Verify MD5 checksum after successful download
		downloadedMD5, err := utils.GetFileMd5(absPath)
		if err != nil {
			log.Printf("[MD5VerificationError]: %v\n", err)
			G.restartDownload(file, absPath, numParts)
			return
		}
		if downloadedMD5 != file.Md5Checksum {
			log.Printf("MD5 checksum mismatch for %s. Expected: %s, Got: %s. Restarting download.\n", file.Name, file.Md5Checksum, downloadedMD5)
			G.restartDownload(file, absPath, numParts)
			return
		}
		fmt.Printf("%s downloaded and verified.\n", file.Name)
	}
}

func (G *GoogleDriveClient) restartDownload(file *drive.File, absPath string, numParts int) {
	log.Printf("Restarting download for %s\n", file.Name)
	os.Remove(absPath)
	success := G.DownloadFile(file, absPath, 0, 1, numParts)
	if success {
		// Verify MD5 checksum after restart
		downloadedMD5, err := utils.GetFileMd5(absPath)
		if err != nil {
			log.Printf("[MD5VerificationError]: %v\n", err)
			return
		}
		if downloadedMD5 != file.Md5Checksum {
			log.Printf("MD5 checksum mismatch after restart for %s. Expected: %s, Got: %s.\n", file.Name, file.Md5Checksum, downloadedMD5)
			os.Remove(absPath)
			return
		}
		fmt.Printf("%s downloaded, restarted, and verified.\n", file.Name)
	}
}

func (G *GoogleDriveClient) DownloadFile(file *drive.File, localPath string, startByteIndex int64, retry int, numParts int) bool {
	if numParts <= 1 {
		return G.downloadSinglePart(file, localPath, startByteIndex, retry)
	}
	return G.downloadMultiPart(file, localPath, startByteIndex, retry, numParts)
}

func (G *GoogleDriveClient) downloadSinglePart(file *drive.File, localPath string, startByteIndex int64, retry int) bool {
	writer, err := os.OpenFile(localPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Printf("[FileOpenError]: %v\n", err)
		return false
	}
	defer writer.Close()

	writer.Seek(startByteIndex, 0)
	request := G.DriveSrv.Files.Get(file.Id).AcknowledgeAbuse(G.abuse).SupportsAllDrives(true)
	request.Header().Add("Range", fmt.Sprintf("bytes=%d-%d", startByteIndex, file.Size))
	response, err := request.Download()
	if err != nil {
		log.Printf("err while requesting download: retrying download: %s: %v\n", file.Name, err)
		if strings.Contains(strings.ToLower(err.Error()), "rate") || response != nil && response.StatusCode >= 500 && retry <= 5 {
			time.Sleep(5 * time.Second)
			return G.downloadSinglePart(file, localPath, startByteIndex, retry+1)
		}
		if strings.Contains(err.Error(), "416: Request range not satisfiable") {
			log.Printf("Received 416 error. Deleting partial file and restarting download from scratch.\n")
			writer.Close()
			os.Remove(localPath)
			return G.downloadSinglePart(file, localPath, 0, retry+1)
		}
		log.Printf("[API-files:get]: (%s) %v\n", file.Id, err)
		return false
	}

	contentLength := response.ContentLength
	if contentLength < 0 || contentLength != file.Size-startByteIndex {
		log.Printf("Inconsistent file size detected. Restarting download from scratch.\n")
		writer.Close()
		os.Remove(localPath)
		return G.downloadSinglePart(file, localPath, 0, retry+1)
	}

	bar := G.GetProgressBar(file.Name, file.Size-startByteIndex)
	proxyReader := bar.ProxyReader(response.Body)
	defer proxyReader.Close()
	bytesWritten, err := io.Copy(writer, proxyReader)
	if err != nil {
		pos, posErr := writer.Seek(0, io.SeekCurrent)
		if posErr != nil {
			log.Printf("Error while getting current file offset, %v\n", err)
			return false
		} else if retry <= MAX_RETRIES {
			log.Printf("err while copying stream: retrying download: %s: %v\n", file.Name, err)
			bar.Abort(true)
			time.Sleep(time.Duration(int64(retry)*2) * time.Second)
			return G.downloadSinglePart(file, localPath, pos, retry+1)
		} else {
			log.Printf("Error while copying stream, %v\n", err)
		}
		return false
	}

	// Ensure the progress bar is completed
	bar.SetTotal(bar.Current(), true)

	totalBytesWritten := startByteIndex + bytesWritten
	if totalBytesWritten != file.Size {
		log.Printf("Mismatch in downloaded file size. Expected: %d, Got: %d. Restarting download from scratch.\n", file.Size, totalBytesWritten)
		writer.Close()
		os.Remove(localPath)
		return G.downloadSinglePart(file, localPath, 0, retry+1)
	}

	// Silent MD5 verification
	downloadedMD5, err := utils.GetFileMd5(localPath)
	if err != nil {
		log.Printf("[MD5VerificationError]: %v\n", err)
		return false
	}
	if downloadedMD5 != file.Md5Checksum {
		log.Printf("MD5 checksum mismatch for %s. Expected: %s, Got: %s. Restarting download.\n", file.Name, file.Md5Checksum, downloadedMD5)
		os.Remove(localPath)
		return G.downloadSinglePart(file, localPath, 0, retry+1)
	}

	G.numFilesDownloaded += 1
	return true
}

func (G *GoogleDriveClient) downloadMultiPart(file *drive.File, localPath string, startByteIndex int64, retry int, numParts int) bool {
	partSize := file.Size / int64(numParts)
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := true

	for i := 0; i < numParts; i++ {
		wg.Add(1)
		go func(partNum int) {
			defer wg.Done()
			partStart := int64(partNum) * partSize
			partEnd := partStart + partSize - 1
			if partNum == numParts-1 {
				partEnd = file.Size - 1
			}

			partPath := fmt.Sprintf("%s.part%d", localPath, partNum)
			partSuccess := G.downloadSinglePart(file, partPath, partStart, retry)
			if !partSuccess {
				mu.Lock()
				success = false
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	if !success {
		return false
	}

	// Merge parts
	writer, err := os.OpenFile(localPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		log.Printf("[FileOpenError]: %v\n", err)
		return false
	}
	defer writer.Close()

	for i := 0; i < numParts; i++ {
		partPath := fmt.Sprintf("%s.part%d", localPath, i)
		partFile, err := os.Open(partPath)
		if err != nil {
			log.Printf("[FileOpenError]: %v\n", err)
			return false
		}
		defer partFile.Close()

		_, err = io.Copy(writer, partFile)
		if err != nil {
			log.Printf("[FileCopyError]: %v\n", err)
			return false
		}

		os.Remove(partPath)
	}

	// Silent MD5 verification
	downloadedMD5, err := utils.GetFileMd5(localPath)
	if err != nil {
		log.Printf("[MD5VerificationError]: %v\n", err)
		return false
	}
	if downloadedMD5 != file.Md5Checksum {
		log.Printf("MD5 checksum mismatch for %s. Expected: %s, Got: %s. Restarting download.\n", file.Name, file.Md5Checksum, downloadedMD5)
		os.Remove(localPath)
		return G.downloadMultiPart(file, localPath, 0, retry+1, numParts)
	}

	G.numFilesDownloaded += 1
	return true
}

func NewDriveClient() *GoogleDriveClient {
	return &GoogleDriveClient{}
}
