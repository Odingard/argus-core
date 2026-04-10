import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const badgeVariants = cva(
  "inline-flex items-center rounded-md border border-oklch(0.92 0.004 286.32) px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-oklch(0.705 0.015 286.067) focus:ring-offset-2 dark:border-oklch(1 0 0 / 10%) dark:focus:ring-oklch(0.552 0.016 285.938)",
  {
    variants: {
      variant: {
        default:
          "border-transparent bg-oklch(0.21 0.006 285.885) text-oklch(0.985 0 0) shadow hover:bg-oklch(0.21 0.006 285.885)/80 dark:bg-oklch(0.92 0.004 286.32) dark:text-oklch(0.21 0.006 285.885) dark:hover:bg-oklch(0.92 0.004 286.32)/80",
        secondary:
          "border-transparent bg-oklch(0.967 0.001 286.375) text-oklch(0.21 0.006 285.885) hover:bg-oklch(0.967 0.001 286.375)/80 dark:bg-oklch(0.274 0.006 286.033) dark:text-oklch(0.985 0 0) dark:hover:bg-oklch(0.274 0.006 286.033)/80",
        destructive:
          "border-transparent bg-oklch(0.577 0.245 27.325) text-destructive-foreground shadow hover:bg-oklch(0.577 0.245 27.325)/80 dark:bg-oklch(0.704 0.191 22.216) dark:hover:bg-oklch(0.704 0.191 22.216)/80",
        outline: "text-oklch(0.141 0.005 285.823) dark:text-oklch(0.985 0 0)",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  )
}

export { Badge, badgeVariants }
