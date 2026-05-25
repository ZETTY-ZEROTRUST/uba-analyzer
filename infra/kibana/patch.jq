if .type == "visualization" then
  if .id == "uba-p3-baseline" then
    .attributes.title = "7팩터 정상 분포 (p99)"
    | .attributes.visState = (
        .attributes.visState
        | fromjson
        | .title = "7팩터 정상 분포 (p99)"
        | .params.time_field = "computed_at"
        | .params.index_pattern = "uba-baseline-*"
        | .params.series[0].terms_field = "metric.keyword"
        | .params.series[0].terms_size = 20
        | .params.series[0].point_size = 4
        | .params.series[0].chart_type = "bar"
        | .params.drop_last_bucket = 1
        | tojson)
  elif .id == "uba-p4-score-alerts" then
    .attributes.title = "시간대별 위험 점수 추이"
    | .attributes.visState = (
        .attributes.visState
        | fromjson
        | .title = "시간대별 위험 점수 추이"
        | tojson)
  elif .id == "uba-p6-top-targets" then
    .attributes.title = "고위험 대상 (Top 20) 추이"
    | .attributes.visState = (
        .attributes.visState
        | fromjson
        | .title = "고위험 대상 (Top 20) 추이"
        | tojson)
  elif .id == "uba-p8-daily-intel" then
    .attributes.title = "일일 캠페인 인텔리전스"
    | .attributes.visState = (
        .attributes.visState
        | fromjson
        | .title = "일일 캠페인 인텔리전스"
        | tojson)
  else . end
elif .type == "search" and .id == "uba-p7-alerts" then
  .attributes.title = "LLM 알람 이력"
elif .type == "dashboard" then
  .attributes.title = "ZETI UBA SOC 대시보드"
  | .attributes.panelsJSON = (
      .attributes.panelsJSON
      | fromjson
      | map(
          if .panelIndex == "1" then .gridData = {x:0, y:0,   w:48, h:22, i:"1"}
          elif .panelIndex == "2" then .gridData = {x:0, y:22, w:48, h:24, i:"2"}
          elif .panelIndex == "3" then .gridData = {x:0, y:46, w:48, h:24, i:"3"}
          elif .panelIndex == "4" then .gridData = {x:0, y:70, w:48, h:28, i:"4"}
          elif .panelIndex == "5" then .gridData = {x:0, y:98, w:48, h:22, i:"5"}
          else . end)
      | tojson)
elif .type == "index-pattern" and .id == "uba-baseline" then
  .attributes.title = "uba-baseline-*"
  | .attributes.timeFieldName = "computed_at"
else . end
