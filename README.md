# Drive-Dl-Go
A Minimal Google Drive Downloader Written in Go

# Features
- Concurrent File Downloads
- Folder Download Support
- Clones Folder on Local as it was structured on G-Drive
- Progress bar with ETA and Speeds
- Custom Path for Downloading file/folder into
- Download from G-Drive Shareable link support 
- Database for storing credentials and token
- Resuming on partially downloaded files
- Skipping Existing files
- Multipart Downloads with Custom Number of Parts and Resume Capability

# Documentation

## Getting Google OAuth API credential file

- Visit the Google Cloud Console
- Go to the OAuth Consent tab, fill it, and save.
- Go to the Credentials tab and click Create Credentials -> OAuth Client ID
- Choose Other/desktop and Create.
- Use the download button to download your credentials.

## Adding Credentials in application's database

`
drivedlgo set <path_to_credentials.json>
`

## Installing via Arch User Repository (For Arch Linux and its Derivatives)

[Package Link](https://aur.archlinux.org/packages/drivedlgo-bin/)

`
yay -S drivedlgo-bin
`

## Using the tool

- Usage can be found in --help
`
drivedlgo --help
`

## Note:-
First time run after set command will authorize the credentials and generate token. 

## Multipart Downloads

To enable multipart downloads, use the `--part` flag followed by the number of parts you want to split the download into. For example, to download a file in 8 parts, use the following command:

`
drivedlgo --part 8 <fileid/link>
`

The parts implementation is smart and resume capable, similar to IDM. Verification takes place as usual after a successful download.
