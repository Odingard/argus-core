import * as React from "react"
import * as TabsPrimitive from "@radix-ui/react-tabs"

import { cn } from "@/lib/utils"

const Tabs = TabsPrimitive.Root

const TabsList = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.List>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.List>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.List
    ref={ref}
    className={cn(
      "inline-flex h-9 items-center justify-center rounded-lg bg-oklch(0.967 0.001 286.375) p-1 text-oklch(0.552 0.016 285.938) dark:bg-oklch(0.274 0.006 286.033) dark:text-oklch(0.705 0.015 286.067)",
      className
    )}
    {...props}
  />
))
TabsList.displayName = TabsPrimitive.List.displayName

const TabsTrigger = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Trigger>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Trigger>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Trigger
    ref={ref}
    className={cn(
      "inline-flex items-center justify-center whitespace-nowrap rounded-md px-3 py-1 text-sm font-medium ring-offset-oklch(1 0 0) transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-oklch(0.705 0.015 286.067) focus-visible:ring-offset-2 disabled:pointer-events-none disabled:opacity-50 data-[state=active]:bg-oklch(1 0 0) data-[state=active]:text-oklch(0.141 0.005 285.823) data-[state=active]:shadow dark:ring-offset-oklch(0.141 0.005 285.823) dark:focus-visible:ring-oklch(0.552 0.016 285.938) dark:data-[state=active]:bg-oklch(0.141 0.005 285.823) dark:data-[state=active]:text-oklch(0.985 0 0)",
      className
    )}
    {...props}
  />
))
TabsTrigger.displayName = TabsPrimitive.Trigger.displayName

const TabsContent = React.forwardRef<
  React.ElementRef<typeof TabsPrimitive.Content>,
  React.ComponentPropsWithoutRef<typeof TabsPrimitive.Content>
>(({ className, ...props }, ref) => (
  <TabsPrimitive.Content
    ref={ref}
    className={cn(
      "mt-2 ring-offset-oklch(1 0 0) focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-oklch(0.705 0.015 286.067) focus-visible:ring-offset-2 dark:ring-offset-oklch(0.141 0.005 285.823) dark:focus-visible:ring-oklch(0.552 0.016 285.938)",
      className
    )}
    {...props}
  />
))
TabsContent.displayName = TabsPrimitive.Content.displayName

export { Tabs, TabsList, TabsTrigger, TabsContent }
