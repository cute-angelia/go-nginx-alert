package main

import (
	"fmt"
	"github.com/cute-angelia/go-utils/cache/nuts"
	"github.com/cute-angelia/go-utils/utils/qcloud/robot"
	"github.com/gotomicro/ego"
	"github.com/gotomicro/ego/core/econf"
	"github.com/nxadm/tail"
	"io"
	"log"
	"strconv"
	"strings"
	"time"
)

var nutsClient *nuts.Component

func init() {
	nutsClient = nuts.Load("default").Build(nuts.WithDir("/tmp/nuts_nginx_alert.db"))
}

const (
	ALERT_500_MIN_LIMIT = 30  // 一分钟60次告警
	ALERT_NOTIFY_DIFF   = 600 // 通知间隔
)

func main() {
	defer nutsClient.Merge()
	ego.New().Invoker(tailfile).Run()
}

func tailfile() error {

	lists := econf.GetStringSlice("alert.list.sites")
	for _, project := range lists {

		accessLog := econf.GetString(fmt.Sprintf("%s.accessLog", project))

		// Create a tail
		t, err := tail.TailFile(accessLog, tail.Config{
			Follow: true,
			ReOpen: true,
			Location: &tail.SeekInfo{
				Whence: io.SeekEnd,
			},
		})
		if err != nil {
			panic(err)
		}

		// Print the text of each received line
		for line := range t.Lines {
			// log.Println(line.Text)
			check502(splitLog(line.Text), project)
		}
	}

	return nil
}

func splitLog(line string) []string {
	return strings.Split(line, " ")
}

func check502(line []string, project string) {
	limit := econf.GetInt(fmt.Sprintf("%s.limit", project))
	wechatKey := econf.GetString(fmt.Sprintf("%s.wechatKey", project))
	if len(wechatKey) == 0 {
		wechatKey = econf.GetString(fmt.Sprintf("%s.wechatKey", "common"))
	}

	bucket := "check502"
	// ip := line[0]
	paths := line[6]
	status := line[8]
	//uri := line[10]
	currentTime, _ := time.Parse("02/Jan/2006:15:04:05 -0700", line[3][1:]+" "+line[4][0:len(line[4])-1])

	key := currentTime.Format("200601021504")

	// log.Println(currentTime, ip, paths, status, uri)
	if paths == "/favicon.ico" {
		return
	}

	statusi, _ := strconv.Atoi(status)

	if statusi >= 400 {
		// 1分钟限制次数
		countlimt := ALERT_500_MIN_LIMIT
		if limit > 0 {
			countlimt = limit
		}

		if count := nutsClient.Incr(bucket, fmt.Sprintf("%s%d", key, statusi), "1", 180); count >= countlimt {
			msg := fmt.Sprintf("告警：项目[%s], 状态[%d] 1分钟超过[%d]次, 路径：%s", project, statusi, count, paths)
			log.Println(msg)
			if nutsClient.IsNotLockedInLimit(bucket, fmt.Sprintf("check502_notify_%s_%d", project, statusi), ALERT_NOTIFY_DIFF, nuts.NewLockerOpt()) {
				robot.Load(wechatKey).Build().SendText(msg)
			}
		}
	}
}
