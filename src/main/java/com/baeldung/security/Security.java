package com.baeldung.nullsafecollectionstreams;

import java.io.File;
import java.io.FileFilter;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;


import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseException;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.BodyDeclaration;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.body.ModifierSet;
import com.github.javaparser.ast.body.TypeDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.SingleMemberAnnotationExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.project.MavenProject;

@Mojo(name = "Security")
public class Security {

	@Parameter(property = "reportFile", defaultValue = "${project.build.directory}/${project.name}-security.csv")
	private String reportFileName;

	@Parameter(property = "basePackage", defaultValue = "com.baeldung")
	private String basePackage;

	@Parameter(defaultValue = "${project}")
	private MavenProject mavenProject;

	public void execute() throws MojoExecutionException {

		FileOutputStream fos;
		try {
			fos = new FileOutputStream(reportFileName);
		} catch (FileNotFoundException e) {
			throw new MojoExecutionException("Cannot create output stream", e);
		}
		PrintWriter pw = new PrintWriter(fos);

		List<String> sourceRoots = (List<String>)mavenProject.getCompileSourceRoots();
		try {
			pw.write("Class Name,Method Name,Description,Roles,\n");
			for (String sourceRoot : sourceRoots) {
				File sourceRootDir = new File(sourceRoot);
				traverse(sourceRootDir, pw);
			}
		} catch (IOException e) {
			throw new MojoExecutionException("IO exception scanning source code", e);
		} catch (ParseException e) {
			throw new MojoExecutionException("Parse exception scanning source code", e);
		} finally {
			pw.flush();
			pw.close();
		}
	}

	private void traverse(File file, PrintWriter pw) throws IOException, ParseException {
		if (file.isDirectory()) {
			for (File child : file.listFiles(new FileFilter() {
				public boolean accept(File pathname) {
					return pathname.isDirectory() ||
							(pathname.getName().endsWith(".java")
									&& (pathname.getName().contains("Bean") || pathname.getName().contains("me")));
				}
			})) {
				traverse(child, pw);
			}
		} else {
			CompilationUnit unit = JavaParser.parse(file);
			for (TypeDeclaration type : unit.getTypes()) {
                if (type instanceof ClassOrInterfaceDeclaration) {
                    ClassOrInterfaceDeclaration intf = (ClassOrInterfaceDeclaration) type;

					AnnotationExpr classRolesAnnotation = null;
					AnnotationExpr classPermitAllAnnotation = null;
					AnnotationExpr classDescriptionAnnotation = null;
					boolean isME = false;
					for (AnnotationExpr annotation : intf.getAnnotations()) {
						if (annotation.getName().getName().equals("RolesAllowed")) {
							classRolesAnnotation = annotation;
						} else if (annotation.getName().getName().equals("PermitAll")) {
							classPermitAllAnnotation = annotation;
						} else if (annotation.getName().getName().equals("Description")) {
							classDescriptionAnnotation = annotation;
						} else if (Arrays.asList("Stateless","Stateful","Local","Remote").contains(annotation.getName().getName())){
							isME = true;
						}
					}

					if (classDescriptionAnnotation != null) {
						Set<String> classDescription = extractAnnotationContents(classDescriptionAnnotation);
						Collection<String> classRoles = extractAnnotationContents(classRolesAnnotation);
						String classRolesString = (classPermitAllAnnotation!= null) ? "[all]" : classRoles.toString().replace(",", ";");

						pw.write(intf.getName() + ",*," + classDescription + "," + classRolesString + ",\n");
						continue;
					}

					if (!isME) continue;

					for (BodyDeclaration member : intf.getMembers()) {
                        if (member instanceof MethodDeclaration) {
                            MethodDeclaration methodDeclaration = (MethodDeclaration) member;
							if (!ModifierSet.isPublic(methodDeclaration.getModifiers())) {
								continue;
							}

							AnnotationExpr methodRolesAnnotation = null;
							AnnotationExpr methodPermitAllAnnotation = null;
							AnnotationExpr methodDescriptionAnnotation = null;
							boolean isUserAccessibleMethod = true;
							for (AnnotationExpr annotation : methodDeclaration.getAnnotations()) {
								if (annotation.getName().getName().equals("RolesAllowed")) {
									methodRolesAnnotation = annotation;
								} else if (annotation.getName().getName().equals("PermitAll")) {
									methodPermitAllAnnotation = annotation;
								} else if (annotation.getName().getName().equals("Description")) {
									methodDescriptionAnnotation = annotation;
								} else if (annotation.getName().getName().equals("PostConstruct") ||
										annotation.getName().getName().equals("PreDestroy")){
									isUserAccessibleMethod = false;
									break;
								}
							}

							if (!isUserAccessibleMethod) continue;

							Set<String> description = extractAnnotationContents(methodDescriptionAnnotation);
							// TODO: Uncomment if it has been decided that we will only print
							// TODO: out those that have descriptions
							if (description.isEmpty()) continue;

							String rolesString = "[all]";
							if (classPermitAllAnnotation == null && methodPermitAllAnnotation == null) {
								Collection<String> classRoles = extractAnnotationContents(classRolesAnnotation);
								Collection<String> methodRoles = extractAnnotationContents(methodRolesAnnotation);

								Collection<String> roles = !methodRoles.isEmpty() ? methodRoles : classRoles;

								// Not user accessible method
								if (roles.size() == 1 && roles.contains("system")) continue;
								if (roles.size() == 2 && roles.contains("system") && roles.contains("system-web")) continue;

								rolesString = roles.toString().replace(",", ";");
							}
							pw.write(intf.getName() + "," + methodDeclaration.getName() + "," + description + "," + rolesString + ",\n");
						}
					}
				}
			}
		}
	}

	private Set<String> extractAnnotationContents(AnnotationExpr annotation) {
		if (annotation == null || !(annotation instanceof SingleMemberAnnotationExpr)) {
			return new TreeSet<String>();
		}
		SingleMemberAnnotationExpr smae = (SingleMemberAnnotationExpr)annotation;
		Set<String> roleNames = new TreeSet<String>();

		// There are instances where in @RolesAllowed("blender.trader") is not a list
		if (smae.getMemberValue().getChildrenNodes().isEmpty()) {
			roleNames.add(((StringLiteralExpr)smae.getMemberValue()).getValue());
		} else {
			for (Node node : smae.getMemberValue().getChildrenNodes()) {
				roleNames.add(((StringLiteralExpr) node).getValue());
			}
		}
		return roleNames;
	}

}
