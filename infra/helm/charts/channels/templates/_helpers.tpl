{{- define "channels.fullname" -}}
{{- printf "%s-channels" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "channels.labels" -}}
app.kubernetes.io/name: channels
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "channels.selectorLabels" -}}
app.kubernetes.io/name: channels
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "channels.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "channels.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "channels.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "channels.fullname" .)) -}}
{{- end -}}
