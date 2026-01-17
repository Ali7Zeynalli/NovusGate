type ProgressBarProps = {
  value: number
  max: number
  color: string
  label?: string
}

export const ProgressBar = ({ value, max, color, label }: ProgressBarProps) => {
  const percentage = max > 0 ? Math.min((value / max) * 100, 100) : 0
  return (
    <div>
      {label && (
        <div className="flex justify-between text-xs mb-1">
          <span className="text-gray-500">{label}</span>
          <span className="text-gray-700 dark:text-gray-300">{percentage.toFixed(1)}%</span>
        </div>
      )}
      <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
        <div
          className={`h-full ${color} transition-all duration-500`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  )
}
