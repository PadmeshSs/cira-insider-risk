import { Tag } from '@/components/ui/Tag'

/** Rows the served model saw in training are in-sample and not detections (N31). */
export function InSampleFlag({ inSample, split }: { inSample: boolean; split?: string }) {
  if (!inSample) return split ? <span className="t-code-sm text-ink-faint">{split}</span> : null
  return (
    <Tag tone="danger" title="The served model was trained on this user's labels (model_split = train). The score is in-sample and is not a detection (N31).">
      in-sample
    </Tag>
  )
}
