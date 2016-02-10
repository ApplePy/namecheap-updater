# Namecheap DNS Updater

A basic python script to update Namecheap DNS A Records providing dynamic DNS on a custom domain.

## Requirements

1) Namecheap must be the name server for your domain.

2) You must generate an API token for updating that domain.

## Updating Hosts

The ddns-updater script can update as many hosts as you would like to your current public IP address. In order to configure the script, see the `example.hosts.json` file for the expected format. This file should be created/renamed as `hosts.json`.

Running the script will read your current IP address and check it against a cache file, this is to prevent you spamming your DNS host with update requests if no update is needed. The cache file is automatically created and resides within the ddns-updater directory as `cachedip.txt`.

When your public IP does not match this cache, an update request will be performed for each entry within the `hosts.json` file.

## Automating the task

The script has been engineered to be a run once update solution at the moment, and as such it is a perfect candidate for `cron`:

```
0,30	*	*	*	* /path/to/ddns-updater/ddns-updater.py > /path/to/ddns-updater/ddns-updater.log
```

That would be a good starting point for running every 30 minutes. It also puts all of the output from the program into a log file rather than letting cron send you emails every 30 minutes!

A bare-bones xml script for adding this to Windows Task Scheduler has also been included; edit as you need!
