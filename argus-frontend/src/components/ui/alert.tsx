import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const alertVariants = cva(
  "relative w-full rounded-lg border border-oklch(0.92 0.004 286.32) px-4 py-3 text-sm [&>svg+div]:translate-y-[-3px] [&>svg]:absolute [&>svg]:left-4 [&>svg]:top-4 [&>svg]:text-oklch(0.141 0.005 285.823) [&>svg~*]:pl-7 dark:border-oklch(1 0 0 / 10%) dark:[&>svg]:text-oklch(0.985 0 0)",
  {
    variants: {
      variant: {
        default: "bg-oklch(1 0 0) text-oklch(0.141 0.005 285.823) dark:bg-oklch(0.141 0.005 285.823) dark:text-oklch(0.985 0 0)",
        destructive:
          "border-oklch(0.577 0.245 27.325)/50 text-oklch(0.577 0.245 27.325) dark:border-oklch(0.577 0.245 27.325) [&>svg]:text-oklch(0.577 0.245 27.325) dark:border-oklch(0.704 0.191 22.216)/50 dark:text-oklch(0.704 0.191 22.216) dark:dark:border-oklch(0.704 0.191 22.216) dark:[&>svg]:text-oklch(0.704 0.191 22.216)",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

const Alert = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & VariantProps<typeof alertVariants>
>(({ className, variant, ...props }, ref) => (
  <div
    ref={ref}
    role="alert"
    className={cn(alertVariants({ variant }), className)}
    {...props}
  />
))
Alert.displayName = "Alert"

const AlertTitle = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLHeadingElement>
>(({ className, ...props }, ref) => (
  <h5
    ref={ref}
    className={cn("mb-1 font-medium leading-none tracking-tight", className)}
    {...props}
  />
))
AlertTitle.displayName = "AlertTitle"

const AlertDescription = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("text-sm [&_p]:leading-relaxed", className)}
    {...props}
  />
))
AlertDescription.displayName = "AlertDescription"

export { Alert, AlertTitle, AlertDescription }
