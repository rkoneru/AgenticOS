{{- define "eval-hub.fullname" -}}
{{- printf "%s-eval-hub" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "eval-hub.labels" -}}
app.kubernetes.io/name: eval-hub
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: axis
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "eval-hub.selectorLabels" -}}
app.kubernetes.io/name: eval-hub
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "eval-hub.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "eval-hub.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "eval-hub.secretName" -}}
{{- .Values.secret.existingSecret | default (printf "%s-secret" (include "eval-hub.fullname" .)) -}}
{{- end -}}
